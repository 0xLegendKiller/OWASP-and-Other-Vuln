# URL :- `https://hackxpert.com/labs/CSTI/00.php`

```text
Client-side template injection vulnerabilities arise when applications using a client-side template framework dynamically embed user input in web pages. When a web page is rendered, the framework will scan the page for template expressions, and execute any that it encounters.
```

## Solution
![image](https://user-images.githubusercontent.com/60841283/151136254-12dcdde4-7a92-4807-acf5-b00177d5dbfd.png)

![image](https://user-images.githubusercontent.com/60841283/151137253-f720c86f-a61d-46a9-938b-485e7fda46ac.png)

Paylaod
```text
{{7*7}}
```

![image](https://user-images.githubusercontent.com/60841283/151136399-46953cab-ea9b-432f-ab0d-e2c4dc93aef2.png)
