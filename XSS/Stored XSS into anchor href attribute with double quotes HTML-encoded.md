# Stored XSS into anchor href attribute with double quotes HTML-encoded

Lab URL :- `https://portswigger.net/web-security/cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded`

![image](https://user-images.githubusercontent.com/60841283/182396467-9920e4f5-a963-4a05-b6a1-27da2b6f7a00.png)

Posting a comment on any blog post 

![image](https://user-images.githubusercontent.com/60841283/182395503-15dcb6d4-a94f-447e-80e8-1e4f268d390d.png)

Looking at that post in burp we see website paramter goes into href tag without sanitization :- 

![image](https://user-images.githubusercontent.com/60841283/182395729-6014171c-7a7e-4050-819e-b0ea7e5e6693.png)

Abusing the tag :- 
Payload :- `javascript:alert(1)`

![image](https://user-images.githubusercontent.com/60841283/182395917-fb8ae048-c69d-4dff-a43c-8e7150cec1f3.png)

![image](https://user-images.githubusercontent.com/60841283/182395959-7f68f60c-c176-44bb-8bb9-d7f6fccf0a42.png)

