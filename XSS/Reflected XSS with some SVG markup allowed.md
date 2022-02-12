# Reflected XSS with some SVG markup allowed
Lab URL :- `https://portswigger.net/web-security/cross-site-scripting/contexts/lab-some-svg-markup-allowed`

In Burp edit search bar payload :- 

Cheatsheet :- `https://portswigger.net/web-security/cross-site-scripting/cheat-sheet`
Normal Payload :- 

![image](https://user-images.githubusercontent.com/60841283/153717718-30b81eb3-cb2b-45b3-b52a-7d2fe7aac0e2.png)

## Fuzzing

* In payload <$$> ,first add Tags in clipboard

![image](https://user-images.githubusercontent.com/60841283/153717552-075f71b2-2db7-486b-8be3-c2bc5ed2577a.png)

We see some Tags don't cause this error such as svg, animatetransform, image, title

![image](https://user-images.githubusercontent.com/60841283/153718263-0890e56f-410c-462f-9750-09c8c18a20df.png)

* Update search payload <svg><animatetransform+$$=1> ,copy Events to Clipboard and paste in payload set.
  
