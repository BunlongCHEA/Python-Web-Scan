"""
Wapiti3 module catalogue + suggestion engine.
Maps each module name to metadata so the UI can suggest
relevant modules based on the target URL.
"""

WAPITI_MODULES = {
    "backup":        {"label": "Backup Files",          "severity": "medium", "desc": "Looks for backup/temp files"},
    "brute_login_form": {"label": "Brute Login Form",   "severity": "high",   "desc": "Brute-forces login forms"},
    "buster":        {"label": "Dir Buster",            "severity": "medium", "desc": "Enumerates hidden paths"},
    "cms":           {"label": "CMS Detection",         "severity": "info",   "desc": "Detects WordPress, Joomla, Drupal…"},
    "crlf":          {"label": "CRLF Injection",        "severity": "medium", "desc": "CRLF / HTTP splitting"},
    "csrf":          {"label": "CSRF",                  "severity": "high",   "desc": "Cross-Site Request Forgery"},
    "exec":          {"label": "Command Execution",     "severity": "critical","desc": "Remote command execution"},
    "file":          {"label": "File Inclusion",        "severity": "critical","desc": "LFI / RFI"},
    "htaccess":      {"label": ".htaccess Bypass",      "severity": "medium", "desc": "Checks .htaccess misconfigs"},
    "htp":           {"label": "HTTP Response Splitting","severity": "medium", "desc": "HTTP response splitting"},
    "ldap":          {"label": "LDAP Injection",        "severity": "high",   "desc": "LDAP injection"},
    "log4shell":     {"label": "Log4Shell (CVE-2021-44228)","severity":"critical","desc":"Log4j RCE"},
    "methods":       {"label": "HTTP Methods",          "severity": "low",    "desc": "Dangerous HTTP methods (PUT/DELETE)"},
    "nikto":         {"label": "Nikto-style Checks",    "severity": "medium", "desc": "Common web server vulnerabilities"},
    "permanentxss":  {"label": "Stored XSS",            "severity": "high",   "desc": "Persistent / stored XSS"},
    "redirect":      {"label": "Open Redirect",         "severity": "medium", "desc": "Unvalidated redirects"},
    "shellshock":    {"label": "Shellshock",            "severity": "critical","desc": "Bash shellshock"},
    "spring4shell":  {"label": "Spring4Shell",          "severity": "critical","desc": "Spring Framework RCE"},
    "sql":           {"label": "SQL Injection",         "severity": "critical","desc": "SQL injection (error-based)"},
    "ssl":           {"label": "SSL/TLS Issues",        "severity": "medium", "desc": "Checks for weak SSL configs"},
    "ssrf":          {"label": "SSRF",                  "severity": "high",   "desc": "Server-Side Request Forgery"},
    "takeover":      {"label": "Subdomain Takeover",    "severity": "high",   "desc": "Dangling DNS / subdomain takeover"},
    "timesql":       {"label": "Blind SQL (Time-based)","severity": "critical","desc": "Time-based blind SQL injection"},
    "upload":        {"label": "File Upload",           "severity": "high",   "desc": "Dangerous file upload"},
    "wapp":          {"label": "Wappalyzer Detect",     "severity": "info",   "desc": "Tech stack fingerprinting"},
    "wp_enum":       {"label": "WordPress Enum",        "severity": "medium", "desc": "WordPress user/plugin enumeration"},
    "xss":           {"label": "XSS (Reflected)",       "severity": "high",   "desc": "Reflected cross-site scripting"},
    "xxe":           {"label": "XXE",                   "severity": "high",   "desc": "XML External Entity"},
    "network_device":{"label": "Network Device",        "severity": "medium", "desc": "Routers / IoT panels"},
    "printer":       {"label": "Printer Detection",     "severity": "low",    "desc": "Exposed printer interfaces"},
}

# Default "safe" modules for any scan
DEFAULT_MODULES = ["wapp", "cms", "methods", "ssl", "backup", "buster"]

def suggest_modules(target_url: str) -> list[str]:
    """Return a suggested list of module names based on URL hints."""
    url_lower = target_url.lower()
    suggested = set(DEFAULT_MODULES)

    keyword_map = {
        "wp-": ["wp_enum", "cms"],
        "wordpress": ["wp_enum", "cms"],
        "joomla": ["cms"],
        "drupal": ["cms"],
        "login": ["brute_login_form", "csrf", "xss"],
        "admin": ["brute_login_form", "htaccess", "methods"],
        "upload": ["upload", "file"],
        "api": ["ssrf", "xxe", "sql"],
        "search": ["xss", "sql", "timesql"],
        "redirect": ["redirect"],
        "https": ["ssl"],
        "xmlrpc": ["xxe"],
        ".php": ["sql", "file", "exec"],
        ".jsp": ["sql", "exec", "spring4shell"],
        ".asp": ["sql", "exec"],
    }

    for keyword, modules in keyword_map.items():
        if keyword in url_lower:
            suggested.update(modules)

    return sorted(suggested)


def severity_badge_color(severity: str) -> str:
    return {
        "critical": "danger",
        "high":     "warning",
        "medium":   "info",
        "low":      "secondary",
        "info":     "light",
    }.get(severity, "light")