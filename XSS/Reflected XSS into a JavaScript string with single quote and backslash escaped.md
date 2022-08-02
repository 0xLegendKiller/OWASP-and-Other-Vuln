# Reflected XSS into a JavaScript string with single quote and backslash escaped

Lab URL :- `https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-single-quote-backslash-escaped`

![image](https://user-images.githubusercontent.com/60841283/182397769-406cf8ec-4b66-4118-b372-5195763085b6.png)

Searching in "Search box" :- 

![image](https://user-images.githubusercontent.com/60841283/182398370-4d6f5c79-3511-401b-90a0-c99551341cce.png)

Search string with `'` :- 

![image](https://user-images.githubusercontent.com/60841283/182398598-6e041bb5-203e-4b54-b88c-b365b830486b.png)

Search string with `"` doesn't get escaped :- 

![image](https://user-images.githubusercontent.com/60841283/182399214-de1e664e-da58-41c2-88b3-899eb33fa878.png)

Closing the script tag and putting XSS payload :- 
Payload in search box :- `test</script><script>alert("test")</script>`

![image](https://user-images.githubusercontent.com/60841283/182399474-2c6303cf-1bf5-46ed-b31a-405ab5320f97.png)

![image](https://user-images.githubusercontent.com/60841283/182399541-ffbf28b1-8e9e-4beb-b98f-6759b44fc5ee.png)
