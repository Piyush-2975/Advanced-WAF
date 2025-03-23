import re

# SQL Injection (SQLi) Patterns
SQLI_PATTERNS = [
    r"(?i)union\s+select", r"(?i)drop\s+table", r"(?i)or\s+1=1", r"--", 
    r"' or '1'='1", r"1' or '1'='1", r"1' or 1=1--", r"(?i)admin'--", r"#",
    r"/\*.*\*/", r"' and '1'='1", r"' and sleep\(", r"(?i)or\s+sleep\(", 
    r"'; drop table users;--", r"'; exec xp_cmdshell\(", r"(?i)or\s+1=1--", 
    r"(?i)waitfor\s+delay", r"(?i)select\s+\*", r"';shutdown --", 
    r"' union all select", r"' and benchmark\(", r"' having 1=1--", 
    r"' and ascii\(", r"' group by columnnames having 1=1--", 
    r"' and extractvalue\(", r"(?i)or\s+'a'='a", r"(?i)1 or 1=1", 
    r"(?i)order by \d+", r"convert\(int,", r"(?i)select username", 
    r"(?i)select password", r"'; waitfor delay '0:0:10'--", 
    r"' OR '1'='1'--", r"(?i)select\s+@@version", r"(?i)select\s+@@datadir", 
    r"(?i)select\s+load_file", r"(?i)select\s+user\(\)", 
    r"(?i)select\s+database\(\)", r"\" OR \"1\"=\"1", r"\' OR \'1\'=\'1"
]

# Cross-Site Scripting (XSS) Patterns
XSS_PATTERNS = [
    r"(?i)<script>", r"(?i)<img src=", r"(?i)onerror=", r"(?i)alert\(", 
    r"(?i)document\.cookie", r"javascript:", r"(?i)<iframe>", r"(?i)<svg>", 
    r"(?i)onmouseover=", r"(?i)onload=", r"(?i)eval\(", r"settimeout\(", 
    r"setinterval\(", r"(?i)innerhtml=", r"(?i)srcdoc=", 
    r"(?i)<link rel=stylesheet href=", r"fetch\(", r"xhr\.open\(", 
    r"window\.location=", r"self\.location=", r"(?i)prompt\(", 
    r"constructor\.constructor\(", r"String\.fromCharCode\(", r"&#x", 
    r"&lt;script&gt;", r"(?i)<body onload=", r"onfocus=", r"onblur=", 
    r"onclick=", r"onkeydown=", r"onkeyup=", r"src=javascript:", 
    r"data:text/html;base64", r"(?i)<embed>", r"(?i)confirm\("
]

# HTML Injection (HTMLi) Patterns
HTMLI_PATTERNS = [
    r"(?i)<div>", r"(?i)<span>", r"(?i)<input", r"(?i)<form", 
    r"(?i)<body", r"(?i)<html", r"(?i)<a href=", r"(?i)<p>", 
    r"(?i)<button>", r"</", r"(?i)<table>", r"(?i)<meta>", r"(?i)<object>", 
    r"(?i)<style>", r"(?i)<textarea>", r"(?i)<fieldset>", 
    r"(?i)<label>", r"(?i)<iframe src=", r"(?i)value=", 
    r"(?i)name=", r"(?i)action=", r"(?i)placeholder=", 
    r"(?i)<marquee>", r"(?i)<select>", r"(?i)<option>", r"(?i)<audio>", 
    r"(?i)<video>", r"(?i)<source>", r"(?i)<track>"
]

# Cross-Site Request Forgery (CSRF) Patterns
CSRF_PATTERNS = [
    r"fetch\(", r"xhr\.open\(", r"xmlhttprequest", r"(?i)<form action=", 
    r"cross-site", r"token=", r"access_token=", r"xsrf-token", 
    r"csrf-token", r"application/x-www-form-urlencoded", 
    r"submitform\(", r"credentials=", r"(?i)<input type=hidden", 
    r"Authorization: Bearer", r"(?i)<form method="
]

# Server-Side Request Forgery (SSRF) Patterns
SSRF_PATTERNS = [
    r"file://", r"gopher://", r"ftp://", r"http://127\.0\.0\.1", 
    r"http://localhost", r"169\.254\.", r"internal", 
    r"metadata\.google\.internal", r"aws", r"azure", 
    r"kubernetes\.default\.svc", r"169\.254\.169\.254", r"127\.0\.0\.53", 
    r"metadata\.", r"0x7f000001", r"0:0:0:0:0:ffff:7f00:1", 
    r"169\.254\.169\.254/latest/meta-data/", r"file:/etc/passwd", 
    r"file:/c:/windows/system32/", r"http://0x7f000001", 
    r"localhost:8080", r"127\.0\.0\.1:3306", r"http://10\.", 
    r"http://192\.168\."
]

# Obfuscation Techniques (Combined into all patterns)
OBFUSCATION_PATTERNS = [
    r"%27", r"%22", r"%3C", r"%3E", r"%3D", r"%2F", r"%5C", r"%3B", r"%00", 
    r"%20", r"%2E%2E%2F", r"\.\./", r"\\\.\.\\", r"\\x", r"%u", 
    r"&#x", r"base64,", r"data:text/html,", r"data:application/json,", 
    r"\\u003c", r"\\u003e", r"\\x3C", r"\\x3E"
]

# Combine all patterns into a single list
MALICIOUS_PATTERNS = SQLI_PATTERNS + XSS_PATTERNS + HTMLI_PATTERNS + CSRF_PATTERNS + SSRF_PATTERNS + OBFUSCATION_PATTERNS
