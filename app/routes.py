"""
routes.py — Flask Blueprint with SSE streaming scan endpoint.
Live logs stream to frontend as scan progresses — no more "stuck" feeling.
"""

import re
import json
import datetime
from flask import Blueprint, request, jsonify, send_from_directory, current_app, Response, stream_with_context

from app.crawler import crawl
from app.injector import run_injections
from app.llm_explainer import LLMExplainer

bp = Blueprint("main", __name__)

ATTACK_LABEL_MAP = {"sqli": 1, "xss": 2, "prompt": 3, "data_leakage": 4}

# ── Rule-based regex patterns ─────────────────────────────────────────────────
SQLI_PATTERNS = [
    r"sql syntax.*?error", r"mysql_fetch", r"mysql_num_rows", r"mysql_query",
    r"you have an error in your sql", r"warning.*?mysql",
    r"ora-\d{5}", r"sqlstate\[", r"pg_query\(\)",
    r"unclosed quotation mark", r"sqlite.*?exception",
    r"microsoft.*?sql.*?server.*?error", r"supplied argument is not a valid mysql",
    r"db error.*?syntax", r"odbc.*?sql",
    r"syntax error.*?near", r"the used select statements have a different number",
]
XSS_PATTERNS = [
    r"<script>alert\(", r"onerror=alert", r"onload=alert",
    r"onfocus=alert", r"onmouseover=alert", r"javascript:alert",
    r"<img.*?onerror=", r"<svg.*?onload=", r"document\.cookie",
    r"<body.*?onload=", r"<input.*?onfocus=",
]
DATA_LEAKAGE_PATTERNS = [
    r"root:x:0:0:", r"/etc/passwd",
    r"sk-[a-zA-Z0-9]{20,}", r"api[_-]?key\s*=\s*['\"][^'\"]{10,}",
    r"password\s*[=:]\s*['\"][^'\"]{4,}",
    r"begin rsa private key", r"-----BEGIN",
    r"aws_access_key_id", r"db_pass.*?=",
    r"eyj[a-zA-Z0-9\-_]{20,}\.[a-zA-Z0-9\-_]{20,}",
]


def rule_based_detect(response_text: str, attack_type: str) -> tuple:
    lower = response_text.lower()
    if attack_type == "sqli":
        for p in SQLI_PATTERNS:
            if re.search(p, lower, re.IGNORECASE):
                return 1, 90
    if attack_type == "xss":
        for p in XSS_PATTERNS:
            if re.search(p, response_text, re.IGNORECASE):
                return 2, 88
    if attack_type == "data_leakage":
        for p in DATA_LEAKAGE_PATTERNS:
            if re.search(p, response_text, re.IGNORECASE):
                return 4, 85
    return 0, 0


def payload_reflection_check(response_text: str, payload: str, attack_type: str) -> tuple:
    """
    Check if the raw payload is reflected in the response.
    Reflected payload = strong indicator of XSS or unescaped input.
    Also checks for SQL error keywords in response when SQLi payload sent.
    """
    if not response_text or not payload:
        return 0, 0

    # XSS: payload reflected unescaped in HTML
    if attack_type == "xss":
        # Check if key parts of the payload appear in raw response
        xss_indicators = [
            "<script>", "alert(", "onerror=", "onload=",
            "javascript:", "<svg", "<img", "onfocus=", "onmouseover="
        ]
        payload_lower = payload.lower()
        response_lower = response_text.lower()
        if payload_lower in response_lower:
            return 2, 92  # Exact payload reflected
        for ind in xss_indicators:
            if ind in payload_lower and ind in response_lower:
                return 2, 80  # Key XSS indicator reflected
    
    # SQLi: error keywords even if subtle
    if attack_type == "sqli":
        sql_hints = [
            "error", "invalid", "syntax", "sql", "mysql", "query",
            "database", "warning", "exception", "odbc", "jdbc",
            "ora-", "pg_", "sqlite", "server error", "500"
        ]
        response_lower = response_text.lower()
        hits = sum(1 for h in sql_hints if h in response_lower)
        if hits >= 3:  # 3+ SQL-related terms in response = suspicious
            return 1, 65

    # Data leakage: sensitive keywords exposed
    if attack_type == "data_leakage":
        leakage_hints = [
            "password", "passwd", "secret", "token", "key", "hash",
            "credential", "internal", "config", "private", "admin"
        ]
        response_lower = response_text.lower()
        hits = sum(1 for h in leakage_hints if h in response_lower)
        if hits >= 4:
            return 4, 60

    return 0, 0


def _sse(data: dict) -> str:
    """Format a dict as an SSE event."""
    return f"data: {json.dumps(data)}\n\n"


@bp.route("/")
def index():
    return send_from_directory(current_app.static_folder, "index.html")


@bp.route("/api/scan-stream")
def scan_stream():
    """
    SSE endpoint: streams scan logs and results in real-time.
    Query param: ?url=<target>
    Events: { type: 'log'|'result'|'error'|'done', ... }
    """
    target_url = request.args.get("url", "").strip()

    if not target_url:
        return Response(_sse({"type": "error", "message": "URL is required."}),
                        mimetype="text/event-stream")

    app = current_app._get_current_object()

    def generate():
        model = app.vuln_model
        if not model.is_loaded():
            yield _sse({"type": "error", "message": "ML model not loaded."})
            return

        explainer = LLMExplainer()

        def log(msg, level="info"):
            return _sse({"type": "log", "message": msg, "level": level})

        yield log(f"Starting scan: {target_url}")
        yield log("Step 1: Crawling target — following links and probing common paths...")

        # ── Crawl ─────────────────────────────────────────────────────────────
        crawl_result = crawl(target_url)

        for err in crawl_result.get("errors", []):
            yield log(err, "info")

        forms = crawl_result["forms"]
        chatbot_endpoints = crawl_result["chatbot_endpoints"]
        crawled_urls = crawl_result["crawled_urls"]

        yield log(f"Crawled {len(crawled_urls)} page(s). Found {len(forms)} form(s), {len(chatbot_endpoints)} chatbot endpoint(s).")

        if not forms and not chatbot_endpoints:
            yield log("No injectable forms found. Site may require JS/auth.", "warning")
            yield _sse({
                "type": "result",
                "data": {
                    "target": target_url, "crawled_pages": len(crawled_urls),
                    "forms_found": 0, "chatbots_found": 0,
                    "vulnerabilities": [], "logs": [],
                    "summary": {"total": 0, "sqli": 0, "xss": 0, "prompt": 0, "data_leakage": 0, "normal": 0}
                }
            })
            yield _sse({"type": "done"})
            return

        # ── Inject payloads ───────────────────────────────────────────────────
        yield log(f"Step 2: Injecting payloads into {len(forms)} form(s)...")
        attempts = run_injections(forms, chatbot_endpoints)
        yield log(f"Completed {len(attempts)} injection attempt(s). Classifying responses...")

        # ── Detect + explain ──────────────────────────────────────────────────
        yield log("Step 3: ML model classifying server responses...")
        vulnerabilities = []
        seen = set()

        for attempt in attempts:
            response_text = attempt.get("response_text", "")
            attack_type = attempt.get("attack_type", "")
            if not response_text:
                continue

            ml_result = model.predict(response_text)
            ml_label = ml_result.get("label", 0)
            ml_conf = ml_result.get("confidence", 0)

            rule_label, rule_conf = rule_based_detect(response_text, attack_type)
            refl_label, refl_conf = payload_reflection_check(response_text, attempt["payload"], attack_type)

            # Pick highest confidence from all three detectors
            best = max(
                (ml_label, ml_conf, "ML"),
                (rule_label, rule_conf, "Rule-Based"),
                (refl_label, refl_conf, "Reflection"),
                key=lambda x: x[1] if x[0] != 0 else 0
            )
            final_label, final_conf, method = best
            if final_label == 0:
                final_label, final_conf, method = ml_label, ml_conf, "ML"

            yield log(f"[{attack_type.upper()}] '{attempt['input_field']}' → {method}: label={final_label} ({final_conf}%)")

            is_vuln = (rule_label != 0) or (
                final_label != 0 and final_conf >= 45 and (
                    final_label == ATTACK_LABEL_MAP.get(attack_type, -1) or final_conf >= 65
                )
            )
            if not is_vuln:
                continue

            dedup = f"{attempt['target_url']}:{attempt['input_field']}:{final_label}"
            if dedup in seen:
                continue
            seen.add(dedup)

            yield log(f"VULNERABILITY: {method} detected label={final_label} on '{attempt['input_field']}' ({final_conf}%)", "warning")

            from app.model import CLASS_NAMES, SEVERITY
            merged = dict(ml_result)
            merged.update({
                "label": final_label,
                "confidence": final_conf,
                "class_name": CLASS_NAMES.get(final_label, "Unknown"),
                "severity": SEVERITY.get(final_label, "INFO"),
                "detection_method": method
            })

            yield log(f"Step 4: Getting AI explanation from SambaNova Llama 3.1...")
            explanation = explainer.explain(
                label=final_label,
                attack_type=merged["class_name"],
                payload=attempt["payload"],
                response_snippet=response_text
            )

            vulnerabilities.append({
                "target_url": attempt["target_url"],
                "input_field": attempt["input_field"],
                "attack_type": attack_type,
                "payload": attempt["payload"],
                "status_code": attempt["status_code"],
                "response_snippet": response_text[:500],
                "ml_result": merged,
                "explanation": explanation,
                "found_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

        summary = {
            "total": len(vulnerabilities),
            "sqli": sum(1 for v in vulnerabilities if v["ml_result"]["label"] == 1),
            "xss": sum(1 for v in vulnerabilities if v["ml_result"]["label"] == 2),
            "prompt": sum(1 for v in vulnerabilities if v["ml_result"]["label"] == 3),
            "data_leakage": sum(1 for v in vulnerabilities if v["ml_result"]["label"] == 4),
            "normal": 0
        }

        level = "warning" if vulnerabilities else "success"
        yield log(f"Scan complete — {len(vulnerabilities)} vulnerability(s) detected.", level)

        yield _sse({
            "type": "result",
            "data": {
                "target": target_url,
                "crawled_pages": len(crawled_urls),
                "forms_found": len(forms),
                "chatbots_found": len(chatbot_endpoints),
                "vulnerabilities": vulnerabilities,
                "logs": [],
                "summary": summary
            }
        })
        yield _sse({"type": "done"})

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive"
        }
    )


# Keep old /api/scan for backward compat (non-streaming fallback)
@bp.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json() or {}
    target_url = (data.get("url") or "").strip()
    if not target_url:
        return jsonify({"error": "URL is required."}), 400
    return jsonify({"message": "Use /api/scan-stream for streaming scan.", "url": target_url}), 200


@bp.route("/api/metrics", methods=["GET"])
def metrics():
    model = current_app.vuln_model
    if not model.is_loaded() or not model.metrics:
        return jsonify({"error": "Model metrics not available."}), 500
    return jsonify(model.metrics)


@bp.route("/api/report", methods=["POST"])
def report():
    data = request.get_json() or {}
    scan_data = data.get("scan_data", {})
    if not scan_data:
        return jsonify({"error": "No scan data provided."}), 400
    return jsonify({"html": _build_report(scan_data)})


import html

def _build_report(scan_data: dict) -> str:
    vulns = scan_data.get("vulnerabilities", [])
    summary = scan_data.get("summary", {})
    target = html.escape(scan_data.get("target", "Unknown"))
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = []
    for i, v in enumerate(vulns, 1):
        ex = v.get("explanation", {})
        sev = html.escape(ex.get("severity", "INFO"))
        ml = v.get("ml_result", {})
        color = {"CRITICAL": "#ff4444", "HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#10b981", "INFO": "#6366f1"}.get(sev, "#94a3b8")
        
        # Escape everything to prevent stored XSS execution in the report itself
        issue_name = html.escape(ex.get('issue', v.get('attack_type','')))
        target_url = html.escape(v.get('target_url', ''))
        input_field = html.escape(v.get('input_field', ''))
        payload = html.escape(v.get('payload', ''))
        status_code = html.escape(str(v.get('status_code', '')))
        impact = html.escape(ex.get('impact','N/A'))
        reason = html.escape(ex.get('reason','N/A'))
        fix = html.escape(ex.get('fix','N/A'))
        vuln_code = html.escape(ex.get('vulnerable_code','N/A'))
        sec_code = html.escape(ex.get('secure_code','N/A'))
        source = html.escape(ex.get('source',''))
        conf = html.escape(str(ml.get('confidence',0)))
        method = html.escape(ml.get('detection_method','ML'))

        rows.append(f"""
        <div class="vuln-card">
          <div class="vuln-header">
            <span class="vuln-num">#{i}</span>
            <span class="vuln-name">{issue_name}</span>
            <span class="sev-badge" style="background:{color}22;color:{color};border:1px solid {color}44">{sev}</span>
            <span class="conf">{conf}% · {method}</span>
          </div>
          <div class="vuln-body">
            <div class="meta-row"><span class="lbl">Target:</span><code>{target_url}</code></div>
            <div class="meta-row"><span class="lbl">Field:</span><code>{input_field}</code></div>
            <div class="meta-row"><span class="lbl">Payload:</span><code class="payload">{payload}</code></div>
            <div class="meta-row"><span class="lbl">HTTP:</span><code>{status_code}</code></div>
            <div class="section-title">Impact</div><p>{impact}</p>
            <div class="section-title">Root Cause</div><p>{reason}</p>
            <div class="section-title">Fix</div><p>{fix}</p>
            <div class="code-grid">
              <div><div class="code-lbl danger">❌ Vulnerable</div><pre class="code-block">{vuln_code}</pre></div>
              <div><div class="code-lbl success">✅ Secure</div><pre class="code-block">{sec_code}</pre></div>
            </div>
            <p style="margin-top:.75rem;font-size:.78rem;color:#64748b">AI Explanation by: {source}</p>
          </div>
        </div>""")

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Report — {target}</title>
<style>*{{box-sizing:border-box;margin:0;padding:0}}body{{font-family:system-ui,sans-serif;background:#0a0e1a;color:#e2e8f0;padding:40px 20px;line-height:1.6}}.container{{max-width:1100px;margin:0 auto}}h1{{font-size:2rem;background:linear-gradient(135deg,#a5b4fc,#6366f1);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:.5rem}}.meta{{color:#64748b;font-size:.9rem;margin-bottom:2.5rem}}.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:2.5rem}}.stat{{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-radius:12px;padding:1.25rem;text-align:center}}.stat-val{{font-size:2rem;font-weight:800;color:#fff}}.stat-label{{font-size:.8rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-top:.25rem}}.vuln-card{{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-radius:14px;margin-bottom:1.5rem;overflow:hidden}}.vuln-header{{display:flex;align-items:center;gap:1rem;padding:1rem 1.5rem;border-bottom:1px solid rgba(255,255,255,.06);flex-wrap:wrap}}.vuln-num{{font-size:.85rem;color:#64748b;font-weight:700}}.vuln-name{{font-size:1.1rem;font-weight:700;color:#fff;flex:1}}.sev-badge{{padding:.3rem .7rem;border-radius:6px;font-size:.75rem;font-weight:700;text-transform:uppercase}}.conf{{font-size:.85rem;color:#64748b;margin-left:auto}}.vuln-body{{padding:1.5rem}}.meta-row{{display:flex;gap:.75rem;align-items:flex-start;margin-bottom:.75rem;font-size:.9rem}}.lbl{{color:#64748b;min-width:100px;font-weight:600;flex-shrink:0}}code{{background:rgba(0,0,0,.4);padding:.2rem .5rem;border-radius:4px;font-family:monospace;font-size:.85rem;word-break:break-all}}.payload{{color:#fb923c}}.section-title{{font-size:.8rem;text-transform:uppercase;letter-spacing:.08em;color:#6366f1;font-weight:700;margin:1.25rem 0 .4rem}}p{{color:#cbd5e1;font-size:.9rem}}.code-grid{{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-top:1rem}}.code-lbl{{font-size:.8rem;font-weight:700;margin-bottom:.4rem}}.code-lbl.danger{{color:#ef4444}}.code-lbl.success{{color:#10b981}}.code-block{{background:rgba(0,0,0,.5);border:1px solid rgba(255,255,255,.06);border-radius:8px;padding:1rem;font-family:monospace;font-size:.82rem;color:#e2e8f0;overflow-x:auto;white-space:pre-wrap}}.no-vuln{{text-align:center;padding:4rem;color:#10b981;font-size:1.2rem}}</style>
</head><body><div class="container">
  <h1>Web Vulnerability Scan Report</h1>
  <div class="meta">Target: <strong>{target}</strong> | Generated: {now} | Educational use only.</div>
  <div class="stats">
    <div class="stat"><div class="stat-val">{summary.get('total',0)}</div><div class="stat-label">Total</div></div>
    <div class="stat"><div class="stat-val" style="color:#ef4444">{summary.get('sqli',0)}</div><div class="stat-label">SQL Injection</div></div>
    <div class="stat"><div class="stat-val" style="color:#f59e0b">{summary.get('xss',0)}</div><div class="stat-label">XSS</div></div>
    <div class="stat"><div class="stat-val" style="color:#a78bfa">{summary.get('prompt',0)}</div><div class="stat-label">Prompt Injection</div></div>
    <div class="stat"><div class="stat-val" style="color:#ff4444">{summary.get('data_leakage',0)}</div><div class="stat-label">Data Leakage</div></div>
  </div>
  {''.join(rows) if rows else '<div class="no-vuln">✅ No vulnerabilities detected.</div>'}
</div></body></html>"""
