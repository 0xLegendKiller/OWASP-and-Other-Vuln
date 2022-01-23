# Forced OAuth profile linking

## Exploit Server Code
```html
<iframe src="https://ac381f451f7657d0c00c7af9000f0008.web-security-academy.net/oauth-linking?code=nyZQhLR75odRVTGdm_pv5Ne3YqeDrFpjcGyPN-ZFcwJ"></iframe>
```

## Exploitation

![image](https://user-images.githubusercontent.com/60841283/150667639-0be4555b-e9da-4da0-b400-438de2ed0580.png)

First request

![image](https://user-images.githubusercontent.com/60841283/150667654-0b9786ed-b78f-4cdf-9add-c983a6e8c720.png)

Social Attach Login

![image](https://user-images.githubusercontent.com/60841283/150667716-0eea6d87-c266-4cdb-bea6-9253ef1cbaf8.png)

![image](https://user-images.githubusercontent.com/60841283/150667770-7b371b4b-6f98-49a2-aea5-2dd98dcc19e5.png)

Capture a valid request just like this and then Copy the request URL and drop the request, this makes sure the code remain valid and then store this in exploit server.

Log out --> Deliver the exploit to victim --> Login direclty via Social Media Link

![image](https://user-images.githubusercontent.com/60841283/150674931-a1ce8e0f-9fc9-41d8-9f94-bc2bcaa5b1c6.png)

![image](https://user-images.githubusercontent.com/60841283/150674771-838e8250-9393-44a0-93ca-0c87f0f470b9.png)

![image](https://user-images.githubusercontent.com/60841283/150674900-149c6450-98db-4ab0-9bc0-cd5b3dcaf681.png)
