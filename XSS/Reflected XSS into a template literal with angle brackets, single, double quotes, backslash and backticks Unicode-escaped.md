# Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped

Lab URL :- `https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-template-literal-angle-brackets-single-double-quotes-backslash-backticks-escaped`

![image](https://user-images.githubusercontent.com/60841283/182524777-83fbbeaf-571e-47f1-8489-f2ce11033e71.png)

Random search string :- `test`

![image](https://user-images.githubusercontent.com/60841283/182525068-f4233a16-e319-4b89-bf5e-e1ed88ca6e4b.png)

With `'` or `"`:- 

![image](https://user-images.githubusercontent.com/60841283/182525189-3f8352a5-022d-4cb6-962f-55ec442b282c.png)

With `>` :- 

![image](https://user-images.githubusercontent.com/60841283/182525397-1682b1fb-6c5f-4115-b63b-c660bf5ad736.png)

No escape for `/` :- 

![image](https://user-images.githubusercontent.com/60841283/182525314-14e98ef5-a317-4f12-95a7-f4f3bb6b5901.png)

Other special charchters :- 

![image](https://user-images.githubusercontent.com/60841283/182526467-efc47903-0f2c-4eac-b829-cb5218f17960.png)

Payload :- `${alert(1)}`

![image](https://user-images.githubusercontent.com/60841283/182526178-d40b7164-9138-4118-adf8-76de55e1a0c1.png)

![image](https://user-images.githubusercontent.com/60841283/182526293-eeaa1fc9-18aa-444b-80f6-1ac25f325b06.png)

![image](https://user-images.githubusercontent.com/60841283/182526222-ba000ac9-1cb2-4783-8d35-867ed9b47877.png)


