# 🛡️ AI Security Scan Report

**Status:** ❌ **SECURITY GATE: FAILED**
**Total Files Scanned:** 2
**Total Findings:** 3
**Scan Errors / Model Failures:** 0

---

## Summary of Findings

| File | Severity | Vulnerability | CWE |
| :--- | :--- | :--- | :--- |
| `.\Tests\SQL_vulnerable.py` | **Critical** | SQL Injection via f-string interpolation in SELECT queries | CWE-89 |
| `.\Tests\XSS_vulnerable.html` | **Critical** | DOM-based XSS via innerHTML | CWE-79 |
| `.\Tests\XSS_vulnerable.html` | **Medium** | URL parameter injection via URLSearchParams | CWE-93 |

---

## Detailed Findings

### 📁 File: `.\Tests\SQL_vulnerable.py`
- **Vulnerability:** SQL Injection via f-string interpolation in SELECT queries (`CWE-89`)
- **Severity:** Critical
- **Explanation:** The code constructs SQL queries using Python f-strings with direct interpolation of user-supplied variables (user_id and user_pw). This allows an attacker to inject arbitrary SQL, enabling full database compromise. For example, a malicious input like `1 OR 1=1 --` would return all rows, or `'; DROP TABLE users; --` could destroy data. The second and third queries are identical and both are vulnerable.
- **Suggested Fix:**
```
Use parameterized queries (prepared statements) with placeholders, e.g., `cursor.execute('SELECT pw FROM users WHERE id = ?', (user_id,))`. Alternatively, use ORM libraries or SQLAlchemy to safely construct queries.
```

### 📁 File: `.\Tests\XSS_vulnerable.html`
- **Vulnerability:** DOM-based XSS via innerHTML (`CWE-79`)
- **Severity:** Critical
- **Explanation:** The application reads the 'name' parameter from the URL query string and injects it directly into the DOM using innerHTML. Because innerHTML parses the string as HTML, an attacker can craft a URL like '?name=<script>alert(1)</script>' to execute arbitrary JavaScript in the victim's browser. This is a classic DOM-based Cross-Site Scripting vulnerability.
- **Suggested Fix:**
```
Use textContent instead of innerHTML to assign the value, or sanitize the input with a library like DOMPurify before injecting. For example: document.getElementById('greeting').textContent = 'Hello, ' + name;
```

### 📁 File: `.\Tests\XSS_vulnerable.html`
- **Vulnerability:** URL parameter injection via URLSearchParams (`CWE-93`)
- **Severity:** Medium
- **Explanation:** The code uses URLSearchParams to parse the query string, which is generally safe, but the resulting 'name' value is then used unsafely. While URLSearchParams itself does not introduce injection, the downstream use of the untrusted value as HTML makes this a DOM XSS vector. The risk is compounded because the attacker controls the entire input path from URL to output.
- **Suggested Fix:**
```
Always treat values parsed from URLSearchParams as untrusted data. Assign them via textContent or sanitize them before any DOM insertion.
```
