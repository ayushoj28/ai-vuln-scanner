"""
llm_explainer.py — SambaNova Llama 3.1 RAG explanations for detected vulnerabilities.
Falls back to local high-quality templates if no API key is set.
"""

import os
import json
import requests

SAMBANOVA_URL = "https://api.sambanova.ai/v1/chat/completions"
SAMBANOVA_MODEL = "Meta-Llama-3.1-8B-Instruct"
DEFAULT_API_KEY = "98f5a48e-3d54-4215-ad4e-c8d222d5bc8c"

# ── Local fallback templates ──────────────────────────────────────────────────
FALLBACK = {
    1: {
        "issue": "SQL Injection",
        "severity": "HIGH",
        "impact": "Attacker can read, modify, or delete database records. May lead to authentication bypass, data theft, or full database takeover.",
        "reason": "The server's response contains SQL error messages or unexpected query output, indicating that user input was directly concatenated into a SQL query without sanitization.",
        "fix": "Use parameterized queries (prepared statements). Never concatenate user input into SQL strings. Use an ORM like SQLAlchemy.",
        "vulnerable_code": "query = f\"SELECT * FROM users WHERE username = '{user_input}'\"\ndb.execute(query)",
        "secure_code": "query = \"SELECT * FROM users WHERE username = %s\"\ndb.execute(query, (user_input,))"
    },
    2: {
        "issue": "Cross-Site Scripting (XSS)",
        "severity": "HIGH",
        "impact": "Attacker can steal session cookies, redirect users, deface pages, or execute malicious scripts in victim browsers.",
        "reason": "The injected script payload was reflected back in the server response without HTML encoding, meaning the browser will execute it as JavaScript.",
        "fix": "Escape all user input before rendering in HTML (use {{ value | e }} in Jinja2). Implement Content Security Policy (CSP) headers.",
        "vulnerable_code": "<!-- Direct output -->\n<div>Hello {{ name }}</div>",
        "secure_code": "<!-- Escaped output -->\n<div>Hello {{ name | e }}</div>\n# Also set header: Content-Security-Policy: default-src 'self'"
    },
    3: {
        "issue": "Prompt Injection",
        "severity": "MEDIUM",
        "impact": "Attacker can hijack the AI assistant's behavior, extract system instructions, bypass safety rules, or exfiltrate confidential data embedded in the system prompt.",
        "reason": "The AI chatbot accepted override instructions from user input, leaking system-level instructions or operating in unintended modes.",
        "fix": "Separate system prompt from user input using role-based message structure. Never concatenate user text into the system prompt. Apply output filtering.",
        "vulnerable_code": "prompt = f\"System: You are a support bot.\\nUser: {user_input}\"\nllm.complete(prompt)",
        "secure_code": "messages = [\n  {\"role\": \"system\", \"content\": \"You are a support bot.\"},\n  {\"role\": \"user\", \"content\": user_input}\n]\nllm.chat(messages)"
    },
    4: {
        "issue": "Data Leakage",
        "severity": "CRITICAL",
        "impact": "Sensitive information such as credentials, API keys, internal paths, or PII exposed to unauthorized parties.",
        "reason": "The server response contained sensitive data including credentials, tokens, internal config, or personally identifiable information that should not be publicly accessible.",
        "fix": "Disable debug mode in production. Implement proper error handling. Never expose stack traces. Sanitize API responses. Use secrets management tools.",
        "vulnerable_code": "# Debug mode on — stack traces exposed\napp.run(debug=True)\n# Error handler missing — raw exception returned to user",
        "secure_code": "# Production config\napp.run(debug=False)\n@app.errorhandler(500)\ndef error(e):\n    return jsonify({\"error\": \"Internal server error\"}), 500"
    },
    0: {
        "issue": "No Vulnerability Detected",
        "severity": "INFO",
        "impact": "None. The server responded normally to the injected payload.",
        "reason": "The server response did not contain any indicators of SQL errors, reflected scripts, leaked data, or prompt bypass patterns.",
        "fix": "Continue applying defense-in-depth: input validation, output encoding, and rate limiting.",
        "vulnerable_code": "N/A",
        "secure_code": "N/A"
    }
}


class LLMExplainer:
    def __init__(self, api_key: str = None):
        # Always use the default key; user-supplied key is optional override
        self.api_key = api_key or DEFAULT_API_KEY

    def explain(self, label: int, attack_type: str, payload: str, response_snippet: str) -> dict:
        """
        Generate vulnerability explanation.
        Uses SambaNova Llama 3.1 if API key is available, otherwise uses local templates.
        """
        if not self.api_key:
            result = dict(FALLBACK.get(label, FALLBACK[0]))
            result["source"] = "Local Knowledge Base"
            return result

        prompt = (
            f"A security scanner detected a potential **{attack_type}** vulnerability.\n\n"
            f"Attack Payload Used: {payload}\n"
            f"Server Response Snippet: {response_snippet[:500]}\n\n"
            f"Respond ONLY with a valid JSON object with these exact keys:\n"
            f"- issue: vulnerability name\n"
            f"- severity: HIGH, MEDIUM, LOW, or CRITICAL\n"
            f"- impact: what an attacker can do\n"
            f"- reason: why the response indicates vulnerability\n"
            f"- fix: step-by-step remediation\n"
            f"- vulnerable_code: short code showing the vulnerability\n"
            f"- secure_code: fixed version of that code\n"
        )

        try:
            resp = requests.post(
                SAMBANOVA_URL,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": SAMBANOVA_MODEL,
                    "messages": [
                        {"role": "system", "content": "You are a cybersecurity expert. Always respond with valid JSON only."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.1
                },
                timeout=15
            )

            if resp.status_code == 200:
                content = resp.json()["choices"][0]["message"]["content"]
                # Strip markdown code fences if present
                content = content.strip()
                if content.startswith("```"):
                    content = content.split("```")[1]
                    if content.startswith("json"):
                        content = content[4:]
                parsed = json.loads(content.strip())
                parsed["source"] = f"SambaNova {SAMBANOVA_MODEL}"
                return parsed

        except Exception as e:
            print(f"[LLM] API error: {e}. Falling back to local templates.")

        result = dict(FALLBACK.get(label, FALLBACK[0]))
        result["source"] = "Local Knowledge Base (API Fallback)"
        return result
