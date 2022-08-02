# Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped

Lab URL :- `https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-double-quotes-encoded-single-quotes-escaped`

![image](https://user-images.githubusercontent.com/60841283/182400400-24a40dff-c860-4391-8c1d-768726d27a0e.png)

Random Search string :- 

![image](https://user-images.githubusercontent.com/60841283/182400581-04a5991c-544b-4a64-99de-42fff0ac00bb.png)

Single quotes escaped when `'` in string :- 

![image](https://user-images.githubusercontent.com/60841283/182400766-e9abbaa5-9812-415a-b7f0-6d92a1f3e50a.png)

Backslash doesn't escapes :- 

![image](https://user-images.githubusercontent.com/60841283/182401815-908c0919-24c5-404e-b777-ec99450dd0b5.png)

Payload in search box :- `test\'-alert(1)//`

![image](https://user-images.githubusercontent.com/60841283/182403140-d8e66235-979e-4948-a40c-76a2884ebec0.png)

![image](https://user-images.githubusercontent.com/60841283/182402798-ee48c348-6310-4585-b215-6cce8fcd4257.png)
