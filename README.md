# Статичиский и динамичиский анализ приложения 

Для проверки были взяты:

Sast:
+ bearer
+ semgrep

Dast:
+ nikto
+ zaproxy

# Bearer
Найдены:

### SQL injection 
```java
rs = stmt.executeQuery(\"select name from users where id='\" + uri.getQueryParameter(\"user_id\") + \"'\"));
```

### Observable Timing Discrepancy

```java
boolean isAdmin = \"admin\".equals(username);
```

### Leakage of information in logger message
```java
logger.info(\"user signed in: \" + user.uuid)
```

# Semgrep

### dockerfile.security.missing-user.missing-user
```Dockerfile
CMD [\"sh\", \"-c\", \"/app/scripts/start.sh\"]
```

### yaml.docker-compose.security.no-new-privileges.no-new-privileges
CWE-732: Incorrect Permission Assignment for Critical Resource

### yaml.docker-compose.security.writable-filesystem-service.writable-filesystem-service
CWE-732: Incorrect Permission Assignment for Critical Resource

### java.lang.security.audit.formatted-sql-string.formatted-sql-string
```java
entityManager.createQuery(\"SELECT p FROM Product p WHERE p.name LIKE '%\" + name + \"%'\")
```

### java.lang.security.audit.formatted-sql-string.formatted-sql-string
```java
entityManager.createQuery(\"SELECT u FROM User u WHERE u.login = '\" + login + \"'\")
```


# Dast
Nikto вроде как нашел больше, но у Zaproxy гараздо более чисемый результат. 


## Nikto
Из за большого объема данных прикреплен как файл Nikto_out.logs


## Zaproxy

```
WARN-NEW: Vulnerable JS Library [10003] x 2 
	http://app:8080/struts/bootstrap/js/bootstrap.min.js?s2b=2.5.1 (200 OK)
	http://app:8080/assets/jquery-3.2.1.min.js (200 OK)
WARN-NEW: Cookie No HttpOnly Flag [10010] x 2 
	http://app:8080/ (200 OK)
	http://app:8080 (200 OK)
WARN-NEW: Cross-Domain JavaScript Source File Inclusion [10017] x 11 
	http://app:8080/ (200 OK)
	http://app:8080/resetPasswordStart.action;jsessionid=1api0h2tz5idd1klg4eailwcf3 (200 OK)
	http://app:8080/home.action (200 OK)
	http://app:8080 (200 OK)
	http://app:8080/resetPasswordStart.action;jsessionid=1jzp60g0bfooklvlq3rbsjf37 (200 OK)
WARN-NEW: Missing Anti-clickjacking Header [10020] x 11 
	http://app:8080/ (200 OK)
	http://app:8080 (200 OK)
	http://app:8080/home.action (200 OK)
	http://app:8080/resetPasswordStart.action;jsessionid=1api0h2tz5idd1klg4eailwcf3 (200 OK)
	http://app:8080/resetPasswordStart.action;jsessionid=1jzp60g0bfooklvlq3rbsjf37 (200 OK)
WARN-NEW: X-Content-Type-Options Header Missing [10021] x 11 
	http://app:8080/ (200 OK)
	http://app:8080/resetPasswordStart.action;jsessionid=1api0h2tz5idd1klg4eailwcf3 (200 OK)
	http://app:8080/home.action (200 OK)
	http://app:8080 (200 OK)
	http://app:8080/assets/fa/css/font-awesome.min.css (200 OK)
WARN-NEW: Server Leaks Version Information via "Server" HTTP Response Header Field [10036] x 11 
	http://app:8080/ (200 OK)
	http://app:8080/sitemap.xml (404 Not Found)
	http://app:8080/robots.txt (404 Not Found)
	http://app:8080/resetPasswordStart.action;jsessionid=1api0h2tz5idd1klg4eailwcf3 (200 OK)
	http://app:8080/home.action (200 OK)
WARN-NEW: Content Security Policy (CSP) Header Not Set [10038] x 11 
	http://app:8080/ (200 OK)
	http://app:8080/robots.txt (404 Not Found)
	http://app:8080/sitemap.xml (404 Not Found)
	http://app:8080/resetPasswordStart.action;jsessionid=1api0h2tz5idd1klg4eailwcf3 (200 OK)
	http://app:8080/home.action (200 OK)
WARN-NEW: Cookie without SameSite Attribute [10054] x 2 
	http://app:8080/ (200 OK)
	http://app:8080 (200 OK)
WARN-NEW: Permissions Policy Header Not Set [10063] x 12 
	http://app:8080/ (200 OK)
	http://app:8080/sitemap.xml (404 Not Found)
	http://app:8080/robots.txt (404 Not Found)
	http://app:8080/resetPasswordStart.action;jsessionid=1api0h2tz5idd1klg4eailwcf3 (200 OK)
	http://app:8080/sitemap.xml. (404 Not Found)
WARN-NEW: Absence of Anti-CSRF Tokens [10202] x 1 
	http://app:8080/register.action (200 OK)
WARN-NEW: Session ID in URL Rewrite [3] x 12 
	http://app:8080/resetPasswordStart.action;jsessionid=1api0h2tz5idd1klg4eailwcf3 (200 OK)
	http://app:8080/resetPasswordStart.action;jsessionid=1api0h2tz5idd1klg4eailwcf3 (200 OK)
	http://app:8080/resetPasswordStart.action;jsessionid=1jzp60g0bfooklvlq3rbsjf37 (200 OK)
	http://app:8080/resetPasswordStart.action;jsessionid=1jzp60g0bfooklvlq3rbsjf37 (200 OK)
	http://app:8080/assessmentHome.action;jsessionid=1api0h2tz5idd1klg4eailwcf3 (200 OK)
WARN-NEW: SQL Injection [40018] x 4 
	http://app:8080/login.action;jsessionid=1api0h2tz5idd1klg4eailwcf3 (302 Found)
	http://app:8080/login.action (302 Found)
	http://app:8080/login.action;jsessionid=1jzp60g0bfooklvlq3rbsjf37 (302 Found)
	http://app:8080/register.action (200 OK)
WARN-NEW: Sub Resource Integrity Attribute Missing [90003] x 11 
	http://app:8080/ (200 OK)
	http://app:8080/resetPasswordStart.action;jsessionid=1api0h2tz5idd1klg4eailwcf3 (200 OK)
	http://app:8080/home.action (200 OK)
	http://app:8080/resetPasswordStart.action;jsessionid=1jzp60g0bfooklvlq3rbsjf37 (200 OK)
	http://app:8080 (200 OK)
WARN-NEW: Cookie Slack Detector [90027] x 30 
	http://app:8080/login.action (0)
	http://app:8080/resetPasswordStart.action (0)
	http://app:8080/login.action;jsessionid=1api0h2tz5idd1klg4eailwcf3 (0)
	http://app:8080 (0)
	http://app:8080/register.action (0)
FAIL-NEW: 0	FAIL-INPROG: 0	WARN-NEW: 14	WARN-INPROG: 0	INFO: 0	IGNORE: 0	PASS: 123
```





