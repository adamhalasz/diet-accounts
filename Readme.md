# Diet: Accounts (in development)
User account management is a general function that we reuse in every application. Accounts is a simple set of API's that you can use as a standard in all your apps. 

With Accounts you can interact with user accounts without touching the backend unless you want to do something more.

### Install
If you are using `diet` it's already installed.
```javascript
npm install diet-accounts
```

### Example Setup
```javascript
// CREATE a new dietjs application
var app = new Application(options);

// SETUP account module
var account = app.accounts({
	table		 : 'users',	   // mysql table
	username      : 'username',	// username column in table
	password	  : 'password',	// password column in table
	select		: '*'	 	   // what to select if user authentication is successfull
});
```

### API
You can interact with your **Accounts** trough these urls on your website:
METHOD | URL  | STATUS |
--- | --- | --- | --- 
**POST**  | `/account/login` | *working*
**POST**  | `/account/logout` | *working*
**POST**  | `/account/update` | *beta*
**POST**  | `/account/changePassword` | *beta*
**POST**  | `/account/delete` | *beta*
**POST**  | `/account/signup` | *beta*
**POST** | `/account/verify` | *beta*
**GET**  | `/account/recover/password` | *beta*
**POST**  | `/account/recover/password` | *beta*

### Default Response from the API's
If the call ends with **success** then:
```javascript
{ success: true, errors: false }
```
If the call  **fails** then:
```javascript
{ success: false, errors:[Array of Errors] }
```

### Customizing the API's
All account actions are accesible via the Accounts API but you can add custom middleware functions too.
 
```javascript
// Custom Login
account.login(function(request, response, mysql){
	// do some custom stuff
	response.end();
	mysql.end();
});

// Custom Logout
account.logout(function(request, response, mysql){
	// do some custom stuff
	response.end();
	mysql.end();
});
```

