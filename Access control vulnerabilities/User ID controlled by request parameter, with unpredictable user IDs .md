# User ID controlled by request parameter, with unpredictable user IDs 
Lab URL :- 

`https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids`

![image](https://user-images.githubusercontent.com/60841283/154508808-4b9a866c-3f35-4a6e-929c-78aac29d0e8d.png)

## Solution
Login with given creds

![image](https://user-images.githubusercontent.com/60841283/154510441-3f3689cf-a863-4286-ba8e-8544f038227a.png)

Looking at the URL :- 

`https://aca41f801efc50b7c0f04fa2000f009f.web-security-academy.net/my-account?id=fb14de61-dc46-4e08-989b-d0133d18059d`

![image](https://user-images.githubusercontent.com/60841283/154510777-3697f441-dc2a-4802-81de-bd49a303fd95.png)

Clicking on user we find his user-id

`https://aca41f801efc50b7c0f04fa2000f009f.web-security-academy.net/blogs?userId=c61fc679-475b-4377-ad8b-4d033dd4f7e3`

Accessing Carlos account.

`https://aca41f801efc50b7c0f04fa2000f009f.web-security-academy.net/my-account?id=c61fc679-475b-4377-ad8b-4d033dd4f7e3`

![image](https://user-images.githubusercontent.com/60841283/154512646-7641d0e0-8f80-4589-81f5-a0044ea48aa2.png)
