# OWASP TOP 2017

## 1. Injection

### 1.1 SQL Injection
> https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

```text
Primary Defenses:

* Use of Prepared Statements (with Parameterized Queries)
* Use of Stored Procedures
* Allow-list Input Validation
* Escaping All User Supplied Input

Additional Defenses:

* Enforcing Least Privilege
* Performing Allow-list Input Validation as a Secondary Defense
```

## 2. Broken Auth
> https://hdivsecurity.com/owasp-broken-authentication

```text
* Implement multi-factor authentication.
* Do not ship or deploy with any default credentials.
* Weak-password checks.
* Limit or increasingly delay failed login attempts.
* Session IDs should not be in the URL.
```

## 3. XSS
> https://portswigger.net/web-security/cross-site-scripting

```text
* Filter input on arrival.
* Encode data on output.
* Use appropriate response headers.
* Content Security Policy.
```

## 4. XML
> https://hdivsecurity.com/owasp-xml-external-entities-xxe

```text
* Use less complex data formats such as JSON, and avoiding serialization of sensitive data.
* Patch or upgrade all XML processors and libraries in use.
* Disable XML external entity and DTD processing in all XML parsers.
* Implement positive ("whitelisting") server-side input validation, filtering, or sanitization.
* SAST tools can help detect XXE in source code/Manual Code review.
```

## 5. Broken Access Control
> https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control

```text
* Except for public resources, deny by default.
* Implement access control mechanisms once and re-use them throughout the application, including minimizing Cross-Origin Resource Sharing (CORS) usage.
* Model access controls should enforce record ownership rather than accepting that the user can create, read, update, or delete any record.
* Unique application business limit requirements should be enforced by domain models.
* Disable web server directory listing and ensure file metadata (e.g., .git) and backup files are not present within web roots.
* Log access control failures, alert admins when appropriate (e.g., repeated failures).
* Rate limit API and controller access to minimize the harm from automated attack tooling.
* Stateful session identifiers should be invalidated on the server after logout. Stateless JWT tokens should rather be short-lived so that the window of opportunity for an attacker is minimized. For longer lived JWTs it's highy recommended to follow the OAuth standards to revoke access.
```

## CSRF
> https://www.netsparker.com/blog/web-security/csrf-cross-site-request-forgery/

```text
* Implement an Anti-CSRF Token
* Use the SameSite Flag in Cookies
```

> https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

```text
* Check if your framework has built-in CSRF protection and use it
	* If framework does not have built-in CSRF protection add CSRF tokens to all state changing requests (requests that cause actions on the site) and validate them on backend
* For stateful software use the synchronizer token pattern
* For stateless software use double submit cookies
* Implement at least one mitigation from Defense in Depth Mitigations section
	* Consider SameSite Cookie Attribute for session cookies but be careful to NOT set a cookie specifically for a domain as that would introduce a security vulnerability that all subdomains of that domain share the cookie. This is particularly an issue when a subdomain has a CNAME to domains not in your control.
	* Consider implementing user interaction based protection for highly sensitive operations
	* Consider the use of custom request headers
	* Consider verifying the origin with standard headers
```

## SSRF
> https://www.neuralegion.com/blog/ssrf-server-side-request-forgery/#preventing-ssrf

```text
* Whitelist Domains in DNS
* Do Not Send Raw Responses
* Enforce URL Schemas
* Enable Authentication on All Services
* Sanitize and Validate Inputs
```
