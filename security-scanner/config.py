# config.py - Felix Chirchir
# Configuration settings for Security Scanner
# Changing settings here affects the entire tool

# ============================================
# DATABASE SETTINGS
# ============================================
DB_CONFIG = {
    "host": "localhost",
    "database": "security_db",
    "user": "felix",
    "password": "felix1234"
}

# ============================================
# SECURITY HEADERS TO CHECK
# Each header has:
# - severity: how bad it is if missing
# - description: what the header does
# - risk: what happens without it
# - recommendation: how to fix it
# ============================================
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "Forces all connections to use HTTPS",
        "risk": "Attackers can intercept unencrypted HTTP traffic",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "X-Frame-Options": {
        "severity": "HIGH",
        "description": "Prevents the page from being embedded in iframes",
        "risk": "Clickjacking attacks can trick users into clicking malicious content",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "Prevents browsers from guessing the content type",
        "risk": "Browsers may execute malicious files disguised as safe content",
        "recommendation": "Add: X-Content-Type-Options: nosniff"
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "Controls which resources the browser is allowed to load",
        "risk": "Cross-site scripting (XSS) attacks can steal user data",
        "recommendation": "Add: Content-Security-Policy: default-src 'self'"
    },
    "X-XSS-Protection": {
        "severity": "MEDIUM",
        "description": "Enables the browser built-in XSS filter",
        "risk": "No browser-level protection against reflected XSS attacks",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block"
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Controls how much referrer information is shared",
        "risk": "Sensitive URLs and user data may leak to third-party sites",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": "MEDIUM",
        "description": "Controls which browser features the site can use",
        "risk": "Site may access camera, microphone, or location without restriction",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"
    }
}

# ============================================
# RISK SCORING
# How many points each severity level is worth
# Used to calculate overall risk score
# ============================================
SEVERITY_SCORES = {
    "CRITICAL": 10,
    "HIGH": 5,
    "MEDIUM": 2,
    "LOW": 1
}

# ============================================
# RISK LEVELS
# Based on total score what is the risk level
# ============================================
RISK_LEVELS = {
    50: "CRITICAL",
    30: "HIGH",
    15: "MEDIUM",
    0: "LOW"
}

# ============================================
# SCAN SETTINGS
# ============================================
TIMEOUT = 10          # Seconds to wait for response
MAX_REDIRECTS = 5     # Maximum redirects to follow
USER_AGENT = "Felix-Security-Scanner/1.0"