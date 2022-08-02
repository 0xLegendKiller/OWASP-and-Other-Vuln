# Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped

Lab URL :- `https://portswigger.net/web-security/cross-site-scripting/contexts/lab-onclick-event-angle-brackets-double-quotes-html-encoded-single-quotes-backslash-escaped`

![image](https://user-images.githubusercontent.com/60841283/182405038-220e7662-3e86-4280-80d0-4c0dde134bef.png)

Positng a comment on any blog post :- 

![image](https://user-images.githubusercontent.com/60841283/182405620-f38199fa-03a8-45ae-8521-00dd4762ab86.png)

View the comment :- 

![image](https://user-images.githubusercontent.com/60841283/182406227-e69daad9-e982-4dbb-867f-6d4f6463116e.png)

Website parameter with `'` :- 

![image](https://user-images.githubusercontent.com/60841283/182408896-4c68304a-f28f-46b8-a9d3-ce24666828fd.png)

No escape

![image](https://user-images.githubusercontent.com/60841283/182413844-3752de62-6bb5-40c6-9d61-8e4e3b186103.png)

Payload for website parameter in alert box :-  `http%3a//foo%3f%26apos%3b-alert(1)-%26apos%3b`

![image](https://user-images.githubusercontent.com/60841283/182411244-4dbab143-bb8c-4fe3-b118-826177b321f0.png)

![image](https://user-images.githubusercontent.com/60841283/182411404-e086ae4e-d4c6-4970-9db6-4a1496dcced3.png)

![image](https://user-images.githubusercontent.com/60841283/182411186-8df338af-a63e-4496-ad6a-5af03dc7c26a.png)
