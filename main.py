# main.py
from flask import Flask, request, jsonify, send_from_directory
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
import os
import json
import time

app = Flask(__name__)

# Whitelist of safe-to-scan domains (educational only)
ALLOWED_DOMAINS = {
    'testphp.vulnweb.com',  # OWASP test site
    'demo.testfire.net',
    'bwa-jwt-for-pentest.s3-website.us-east-2.amazonaws.com',
    'dvwa.local',
    'mutillidae.local'
}

def is_allowed_domain(url):
    """Check if domain is in our educational whitelist"""
    try:
        domain = urlparse(url).netloc.lower()
        return domain in ALLOWED_DOMAINS
    except:
        return False

@app.route('/')
def home():
    """Serve the frontend"""
    return send_from_directory('.', 'index.html')

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy", 
        "service": "SCNBugDefinerX",
        "allowed_domains": list(ALLOWED_DOMAINS),
        "message": "Only educational targets permitted"
    })

@app.route('/scan', methods=['POST'])
def scan():
    """Main scanning endpoint"""
    start_time = time.time()
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400

    # Ensure URL has scheme
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # 🔒 Domain restriction for ethical scanning
    if not is_allowed_domain(url):
        return jsonify({
            "error": "Domain not allowed for scanning",
            "allowed_domains": list(ALLOWED_DOMAINS),
            "warning": "Only educational targets permitted for security testing"
        }), 403

    findings = []
    headers = {}
    html = ""
    final_url = url

    try:
        # Configure session for better scanning
        session = requests.Session()
        session.headers.update({'User-Agent': 'SCNBugDefinerX/1.0'})
        session.max_redirects = 5

        # Fetch the page
        response = session.get(
            url,
            timeout=15,
            verify=False,  # Skip SSL verification for testing sites
            allow_redirects=True
        )
        
        final_url = response.url
        headers = dict(response.headers)
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')

        # 1. 🔐 Security Headers Check
        security_headers = {
            'Strict-Transport-Security': {
                'desc': 'HSTS missing - vulnerable to protocol downgrade attacks',
                'severity': 'High',
                'remediation': 'Add HSTS header with max-age=31536000'
            },
            'Content-Security-Policy': {
                'desc': 'CSP missing - high risk of XSS and injection attacks',
                'severity': 'High',
                'remediation': 'Implement comprehensive CSP policy'
            },
            'X-Frame-Options': {
                'desc': 'Clickjacking vulnerability - site can be embedded in frames',
                'severity': 'Medium',
                'remediation': 'Set X-Frame-Options: DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'desc': 'MIME sniffing allowed - potential drive-by downloads',
                'severity': 'Medium',
                'remediation': 'Set X-Content-Type-Options: nosniff'
            },
            'X-XSS-Protection': {
                'desc': 'Legacy XSS protection disabled',
                'severity': 'Low',
                'remediation': 'Enable X-XSS-Protection: 1; mode=block'
            },
            'Referrer-Policy': {
                'desc': 'Referrer policy not set - potential information leakage',
                'severity': 'Low',
                'remediation': 'Set Referrer-Policy: strict-origin-when-cross-origin'
            }
        }

        for header, info in security_headers.items():
            if header not in headers:
                findings.append({
                    "id": f"missing-{header.lower().replace('-', '')}",
                    "title": f"Security Header Missing: {header}",
                    "severity": info['severity'],
                    "category": "Security Misconfiguration",
                    "description": info['desc'],
                    "location": final_url,
                    "remediation": [info['remediation']],
                    "references": ["https://owasp.org/www-project-secure-headers/"]
                })

        # 2. 🧪 SQL Injection Detection
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '/')
            method = form.get('method', 'GET').upper()
            form_url = urljoin(final_url, action)
            
            # Check input fields for potential SQLi
            inputs = form.find_all(['input', 'textarea'])
            for inp in inputs:
                name = inp.get('name') or inp.get('id')
                if name:
                    # Test for SQLi by checking error patterns
                    test_payloads = ["'", "';", "' OR '1'='1", "' OR 1=1--"]
                    for payload in test_payloads[:2]:  # Limit to 2 for speed
                        test_param = {name: payload}
                        try:
                            test_response = session.request(
                                method, form_url, 
                                params=test_param if method == 'GET' else None,
                                data=test_param if method == 'POST' else None,
                                timeout=8,
                                verify=False
                            )
                            
                            # Look for SQL error patterns
                            sql_patterns = [
                                (r"SQL syntax.*MySQL", "MySQL syntax error detected"),
                                (r"PostgreSQL.*ERROR", "PostgreSQL error exposed"),
                                (r"sqlite.*error", "SQLite error in response"),
                                (r"ORA-[0-9]{5}", "Oracle DB error code"),
                                (r"Microsoft SQL Server.*error", "MSSQL error exposed"),
                                (r"supplied argument is not a valid MySQL", "MySQL function error"),
                                (r"mysql_fetch", "MySQL fetch error"),
                                (r"execute query", "Query execution error")
                            ]
                            
                            for pattern, desc in sql_patterns:
                                if re.search(pattern, test_response.text, re.I):
                                    findings.append({
                                        "id": f"sqli-{name}-{hash(pattern)}",
                                        "title": "SQL Injection Vulnerability [CRITICAL]",
                                        "severity": "Critical",
                                        "category": "Injection Attack",
                                        "description": f"Database error message indicates potential SQL injection vulnerability in parameter '{name}'.",
                                        "location": form_url,
                                        "evidence": f"Payload '{payload}' triggered: {desc}",
                                        "remediation": [
                                            "Use parameterized queries/prepared statements",
                                            "Implement strict input validation and sanitization",
                                            "Deploy Web Application Firewall (WAF)",
                                            "Use ORM frameworks"
                                        ],
                                        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"]
                                    })
                                    break
                                    
                        except requests.exceptions.RequestException:
                            continue
                        break  # Test only one payload per field

        # 3. 🧪 Cross-Site Scripting (XSS) Detection
        for form in forms:
            action = form.get('action', '/')
            form_url = urljoin(final_url, action)
            inputs = form.find_all(['input', 'textarea'])
            
            for inp in inputs:
                name = inp.get('name') or inp.get('id')
                if name:
                    # Test for reflected XSS
                    xss_test = f"xss_test_{''.join([str(ord(c)) for c in 'XSS'[:3]])}"
                    test_params = {name: xss_test}
                    
                    try:
                        test_response = session.get(form_url, params=test_params, timeout=8, verify=False)
                        
                        # Check if input is reflected in response
                        if xss_test in test_response.text:
                            # Check for dangerous HTML contexts
                            dangerous_patterns = [
                                r"<script.*?>.*?" + re.escape(xss_test),
                                r"on\w+\s*=\s*['\"].*?" + re.escape(xss_test),
                                r"javascript:.*?" + re.escape(xss_test),
                                re.escape(xss_test) + r".*?<\/(input|textarea)"
                            ]
                            
                            is_dangerous = any(re.search(pattern, test_response.text, re.I) for pattern in dangerous_patterns)
                            
                            severity = "High" if is_dangerous else "Medium"
                            findings.append({
                                "id": f"xss-{name}",
                                "title": f"Potential XSS: Input '{name}' is reflected",
                                "severity": severity,
                                "category": "Cross-Site Scripting (XSS)",
                                "description": f"User input parameter '{name}' appears to be reflected in the response without proper sanitization, indicating potential XSS vulnerability.",
                                "location": form_url,
                                "evidence": f"Parameter '{name}' reflects value '{xss_test}' in response",
                                "remediation": [
                                    "Escape all user input before rendering",
                                    "Implement strong Content-Security-Policy",
                                    "Use frameworks with auto-escaping (React, Angular)",
                                    "Validate and sanitize all input"
                                ],
                                "references": ["https://owasp.org/www-community/attacks/xss/"]
                            })
                            
                    except requests.exceptions.RequestException:
                        pass

        # 4. 📦 Outdated JavaScript Libraries
        scripts = soup.find_all('script', src=True)
        library_patterns = {
            'jquery': (r'jquery[.\-]((?:\d+\.)?(?:\d+\.)?(?:\d+))', '3.5.0'),
            'react': (r'react[.\-]((?:\d+\.)?(?:\d+\.)?(?:\d+))', '18.0.0'),
            'angular': (r'angular[.\-]((?:\d+\.)?(?:\d+\.)?(?:\d+))', '14.0.0'),
            'vue': (r'vue[.\-]((?:\d+\.)?(?:\d+\.)?(?:\d+))', '3.0.0')
        }
        
        for script in scripts:
            src = script['src']
            full_url = urljoin(final_url, src)
            
            for lib_name, (pattern, min_version) in library_patterns.items():
                match = re.search(pattern, src, re.I)
                if match:
                    version = match.group(1)
                    if version and is_version_older_than(version, min_version):
                        findings.append({
                            "id": f"outdated-{lib_name}",
                            "title": f"Outdated {lib_name.capitalize()} Detected (v{version})",
                            "severity": "High" if lib_name == 'jquery' else "Medium",
                            "category": "Vulnerable Components",
                            "description": f"Older version of {lib_name.capitalize()} is vulnerable to known security issues.",
                            "location": full_url,
                            "evidence": f"Version {version} detected via script src",
                            "remediation": [
                                f"Upgrade to {lib_name.capitalize()} {min_version} or later",
                                "Use Subresource Integrity (SRI)",
                                "Load from trusted CDN with version pinning"
                            ],
                            "references": [f"https://{lib_name}.js.org" if lib_name != 'jquery' else "https://jquery.com/security/"]
                        })

        # 5. 🕵️ Information Disclosure
        info_patterns = [
            ('debug', 'Debug mode enabled'),
            ('xdebug', 'XDebug enabled in production'),
            ('localhost', 'Internal host reference'),
            ('127.0.0.1', 'Internal IP address exposed'),
            ('admin', 'Admin interface exposed'),
            ('backup', 'Backup file reference'),
            ('config', 'Configuration file reference'),
            ('password', 'Password field exposed'),
            ('secret', 'Secret key exposed')
        ]
        
        for pattern, desc in info_patterns:
            if pattern in html.lower():
                findings.append({
                    "id": f"info-{pattern}",
                    "title": f"Information Disclosure: '{pattern}' found",
                    "severity": "Low",
                    "category": "Information Disclosure",
                    "description": f"Potential sensitive information exposed in HTML source: {desc}",
                    "location": "HTML Source Code",
                    "evidence": f"Keyword '{pattern}' found in page content",
                    "remediation": [
                        "Remove sensitive information from production code",
                        "Use environment variables for secrets",
                        "Implement proper access controls"
                    ]
                })
        
        # Check server headers
        server_header = headers.get('Server', '')
        powered_header = headers.get('X-Powered-By', '')
        
        if server_header:
            findings.append({
                "id": "server-header",
                "title": f"Server Version Exposed: {server_header}",
                "severity": "Low",
                "category": "Information Disclosure",
                "description": "Web server version disclosure can help attackers target known vulnerabilities.",
                "location": "HTTP Server Header",
                "remediation": ["Hide server version", "Use generic server tokens"]
            })
            
        if powered_header:
            findings.append({
                "id": "powered-by",
                "title": f"Technology Stack Exposed: {powered_header}",
                "severity": "Low",
                "category": "Information Disclosure",
                "description": "Backend technology stack exposed in headers.",
                "location": "X-Powered-By Header",
                "remediation": ["Remove X-Powered-By header"]
            })

        # 6. 🔐 Cookie Security
        for cookie in response.cookies:
            if not cookie.secure and final_url.startswith('https'):
                findings.append({
                    "id": f"cookie-secure-{cookie.name}",
                    "title": f"Cookie '{cookie.name}' Missing Secure Flag",
                    "severity": "Medium",
                    "category": "Session Management",
                    "description": f"Cookie '{cookie.name}' is transmitted over HTTP and HTTPS, vulnerable to interception.",
                    "location": "Cookie Header",
                    "remediation": [
                        "Add Secure flag to cookie",
                        "Ensure cookies are only sent over HTTPS"
                    ]
                })

            if not getattr(cookie, 'httponly', False):
                findings.append({
                    "id": f"cookie-httponly-{cookie.name}",
                    "title": f"Cookie '{cookie.name}' Missing HttpOnly Flag",
                    "severity": "Medium",
                    "category": "Session Management",
                    "description": f"Cookie '{cookie.name}' is accessible via JavaScript, vulnerable to XSS theft.",
                    "location": "Cookie Header",
                    "remediation": [
                        "Add HttpOnly flag to cookie",
                        "Prevent JavaScript access to sensitive cookies"
                    ]
                })

    except requests.exceptions.SSLError:
        findings.append({
            "id": "ssl-error",
            "title": "SSL Certificate Invalid",
            "severity": "High",
            "category": "TLS Security",
            "description": "SSL certificate is invalid, self-signed, or expired.",
            "location": url,
            "remediation": ["Install valid certificate from trusted CA", "Use Let's Encrypt for free certificates"]
        })
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Failed to connect to target. Check URL and network connectivity."}), 500
    except requests.exceptions.Timeout:
        return jsonify({"error": "Request timed out. Target may be slow or blocking requests."}), 500
    except requests.exceptions.TooManyRedirects:
        return jsonify({"error": "Too many redirects. Possible redirect loop."}), 500
    except Exception as e:
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

    # Calculate overall score
    score = 100
    for finding in findings:
        if finding["severity"] == "Critical": score -= 15
        elif finding["severity"] == "High": score -= 10
        elif finding["severity"] == "Medium": score -= 5
        elif finding["severity"] == "Low": score -= 2
    
    score = max(0, min(100, round(score)))
    scan_duration = time.time() - start_time

    return jsonify({
        "url": final_url,
        "overall_score": score,
        "vulnerabilities": findings,
        "scan_time": round(scan_duration, 2),
        "disclaimer": "This is a passive security assessment. No destructive testing was performed.",
        "scan_details": {
            "cookies_found": len(response.cookies),
            "forms_found": len(forms) if 'forms' in locals() else 0,
            "scripts_found": len(scripts) if 'scripts' in locals() else 0,
            "redirects_followed": len(response.history) if 'response' in locals() else 0
        }
    })

def is_version_older_than(current, minimum):
    """Compare versions to check if current version is older than minimum"""
    try:
        current_parts = list(map(int, (current.split('.') + [0,0,0])[:3]))
        min_parts = list(map(int, (minimum.split('.') + [0,0,0])[:3]))
        
        for i in range(3):
            if current_parts[i] < min_parts[i]:
                return True
            elif current_parts[i] > min_parts[i]:
                return False
        return False
    except:
        return True  # Assume vulnerable if can't parse

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)