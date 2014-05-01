// Diet-Accounts 
function Authenticate(setup){
	if(!setup)      var setup = {};
	if(!setup.table) 	setup.table 	= 'users';
	if(!setup.username) setup.username 	= 'username';
	if(!setup.password) setup.password 	= 'password';
	if(!setup.select) 	setup.select 	= '*';
	
	var Auth = hook(setup, {});
	Auth.createSession = function(password){
		// create unique session key
		var key = sha1(uniqid());
		var cipher = crypto.createCipher('aes192', password);
		cipher.update(key, 'binary', 'hex');
		return cipher.final('hex') ;
		 
	}
	Auth.setup = function(username, password, mysql){
		this.username = username;
		this.password = password;
		var auth = this;
		this.run = function(){
			var username 	  = auth.username.toLowerCase();
			var sha1_password = crypto.createHash('sha1');
			var sha1_password = sha1_password.update(auth.password);
				sha1_password = sha1_password.digest('hex');
			
			mysql('SELECT '+setup.select+' FROM '+setup.table+' WHERE '+setup.username+' = \'' + auth.username + '\' AND '+setup.password+' = \'' + sha1_password + '\'',
			function(rows, errors){
				if(isset(rows)){
					if(rows.length == 1){ 
						rows[0].session = Auth.createSession(sha1_password);
						mysql.accounts.update('id', rows[0].id, {session: rows[0].session}, function(){
							auth.success(rows[0]);
						});
					} else { 
						auth.failed(); 
					}
				} else {
					auth.failed();
				}
			});
		}
		return auth;
	}
	Auth.login = function(response, session, redirect){
		response.cookies.set('id', session, { time: [365,0,0], httpOnly: true, path: '/' });
		if(isset(redirect)) { response.redirect(redirect); }
	}
	Auth.logout = function(request, response, mysql, redirect, callback){

		mysql.accounts.update('session', request.cookies.id, { session: 0 }, function(){
			response.cookies.delete('id');
			if(isset(redirect)) { response.redirect(redirect); }
			if(callback) callback();
		});
	}
	return Auth;
}

/* Account API'S
	
	// working
	/account/login
	/account/logout
	/account/update
	/account/changePassword
	/account/delete
	/account/language
	/account/signup
	
	// todo
	/account/verify
	/account/recover
	/account/recover/password
	/account/changeEmail

*/

module.exports = function(app){
	
	var whiteList = [app.domain];
	
	var cors = function(request, response){
		console.log(request.headers.origin);
		if(isset(request.headers.origin)){
			var sso_whitelist 	= whiteList;
			var domain 			= url.parse(request.headers.origin);
			var origin 			= domain.protocol + '//' + domain.hostname;
			if(inArray(origin, sso_whitelist)){
				response.setHeader('Access-Control-Allow-Origin', origin);
				response.setHeader('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE');
				response.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Set-Cookie');
				response.setHeader('Access-Control-Allow-Credentials', 'true')
			}
		}
	}
	
	var events = {};
	
	// Setup Authenticate system
	app.accounts = function(input){
		var protected = (input.protected) ? ['id'].concat(input.protected) : ['id'] ;
		var options = {
			table	 	: input.table 	|| 'accounts',
			username 	: input.username  || 'email',
			password 	: input.password	|| 'password',
			select	 	: input.select	|| '*',
			protected	: protected,
			change_password	: {
				old_password		: input.old_password 	   || 'old_password',
				new_password		: input.new_password 	   || 'new_password',
				new_password_again	: input.new_password_again || 'new_password_again',
			}
		};
		
		Auth = Authenticate(options);
		app.accounts.options = options;
		app.accounts.auth = Auth;
		
		if(options.whitelist) options.whitelist.forEach(function(domain){ whiteList.push(domain); });
	}
	
	
	app.accounts.on = function(event, callback){ events[event] = callback; }	
	
	// ====================( Account / Login ) ====================
	app.post('/accounts/login', function(request, response, mysql){
		var auth = Auth.setup(
			request.body[app.accounts.options.username], 
			request.body[app.accounts.options.password], mysql);
			 
		auth.success = function(user){
			Auth.login(response, user.session);
			if(events.login){ 
				events.login(request, response, mysql, user.session); 
			}  else {
				response.success({ session: user.session });
				mysql.end();
			}
		};
		auth.failed	= function(){
			request.error('password', 'Email or password doesn\'t match.');
			if(events.login){ 
				events.login(request, response, mysql);
			} else {
				response.error();
				mysql.end();
			}
		};
		auth.run();
	});
	/*
	app.post.simple('/account/autoLogin', function(request, response, mysql){
		cors(request, response);
		console.log('## SET COOKIE ON ', request.url.hostname, ' SESSION = ', request.body.session );
		console.log(request.headers);
		Auth.login(response, request.body.session);
		console.log('## Set-Cookie: ', response.getHeader('set-cookie'));
		response.end(JSON.stringify({passed: true, errors: false, session: request.body.session}));
	});*/
	
	// ====================( Account / Logout ) ====================
	app.get('/accounts/logout', function(request, response, mysql){
		if(events.logout){
			Auth.logout(request, response, mysql, false, function(){
				events.logout(request, response, mysql);
			});
		} else {
			cors(request, response);
			var redirect = !isset(request.query.sso) ? 'back' : false ;
			Auth.logout(request, response, mysql, redirect);
			if(!redirect) response.end({passed: true, errors: false});
		}
	});
	
	// ====================( Account / Update ) ====================
	app.post('/accounts/update', function(request, response, mysql){
		if(isset(response.head.account.id)){
			var input = { id: response.head.account.id };
			for(column in request.body){
				if(!inArray(column, app.accounts.options.protected)){
					input[column] = request.body[column];
				} else {
					request.error(column, 'PROTECTED_COLUMN');
				}
			}
			if(request.passed){
				mysql.accounts.save(input, function(rows, onerror, sql){
					if(events.update){
						events.update(request, response, mysql);
					} else {
						response.success();
						mysql.end();
					}
				});
			} else {
				if(events.update){
					events.update(request, response, mysql);
				} else {
					response.error();
					mysql.end();
				}
			}
		} else {
			request.error('account', 'NOT_AUTHORIZED');
			if(events.update){
				events.update(request, response, mysql);
			} else {
				response.error();
				mysql.end();
			}
		}
	});
	
	// ====================( Account / Sign Up ) ====================
	app.post('/accounts/create', function(request, response, mysql){
		if(events.create){
			events.create(request, response, mysql);
		} else {
			response.notFound();
		}
		/*
		// FORM check
		request.check('signup_first_name');
		request.check('signup_last_name');
		request.check('signup_email').isEmail();
		request.check('signup_password').length(3, 254);
		
		// EMAIL check
		function VerifyEmail(callback){
			mysql.accounts.get('email', request.body.signup_email, function(rows){
				if(rows.length){ request.error('signup_email', 'already exists'); } 
				callback();
			})
		}
		
		VerifyEmail(function(){
			if(request.passed){
				var activation_code = uniqid();
				
				// Create User
				mysql.accounts.create({
					first_name	: request.body.signup_first_name,
					last_name	: request.body.signup_last_name,
					email		: request.body.signup_email,
					password	: sha1(request.body.signup_password),
					activated	: activation_code,
				}, function(rows){
					
					// Send Email Confirmation
					mail.send({
						subject		: response.head.echo('Email Verification'),
						to 			: request.body.signup_email,
						template	: 'account_activation',
						data		: {
							first_name	: request.body.signup_first_name,
							activated	: activation_code,
							echo 		: response.head.echo
						}
					});
					
					response.success();
				});
				
			} else {
				response.error();
			}
		});*/
	}); 
	
	// ====================( Account / Change Password ) ====================
	
	app.post('/accounts/change_password', function(request, response, mysql){
		if(isset(response.head.account.id)){
			var options = app.accounts.options.change_password;
			request.demand(options.new_password).length(3, 254);
			request.demand(options.new_password).equals(
				request.body[options.new_password_again]);
			
			// check old password
			mysql.accounts.get('id', response.head.account.id, function(rows){                    
				if(sha1(request.body[options.old_password]) != rows[0].password){
					request.errors[options.old_password] = 'not correct';
					request.passed = false;
				} 
				finish();
			});
			
			function finish(){
				if(request.passed){
					mysql.accounts.save({
						id			: response.head.account.id,
						password	: sha1(request.body[options.new_password])
					}, function(){
						if(events.change_password){
							events.change_password(request, response, mysql);
						} else {
							response.success();
							mysql.end();
						}
					});
				} else {
					if(events.change_password){
						events.change_password(request, response, mysql);
					} else {
						response.error();
						mysql.end();
					}
				}
			}
		} else {
			request.error('account', 'NOT_AUTHORIZED');
			if(events.change_password){
				events.change_password(request, response, mysql);
			} else {
				response.error();
				mysql.end();
			}
		}
	});
	
	// ====================( Account / Delete ) ====================
	app.post('/account/delete', function(request, response, mysql){
		if(isset(response.head.account.id)){
			// check password
			mysql.accounts.get('session', response.head.account.id, function(rows){  
				var user = rows[0];                  
				if(sha1(request.body.password) != user.password){
					response.end('Password is incorrect');
				}  else {
					var next = new Next(4, finish);
					// delete account
					mysql.accounts.delete('session', response.head.account.id, next);
					
					// delete reviews
					mysql.reviews.delete('owner', response.head.account.id, next);
					
					// delete portfolio
					mysql.portfolio.get('owner', response.head.account.id, function(rows){
						rows.forEach(function(picture){
							fs.unlinkSync(app.public + '/uploads/portfolio/original/'	+ picture.name);
							fs.unlinkSync(app.public + '/uploads/portfolio/thumbnail/'	+ picture.name);
						});
						mysql.portfolio.delete('owner', response.head.account.id, next);
					});
					
					// delete avatars
					if(isset(user.avatar)){
						fs.unlinkSync(app.public + '/uploads/avatar/original/'	+ user.avatar);
						fs.unlinkSync(app.public + '/uploads/avatar/thumbnail/'	+ user.avatar);
						fs.unlinkSync(app.public + '/uploads/avatar/small/'		+ user.avatar);
						fs.unlinkSync(app.public + '/uploads/avatar/tiny/' 		+ user.avatar);
					}
					// delete services
					mysql.services.delete('owner', response.head.account.id, next);
					
					function finish(){
						Auth.logout(request, response, mysql, 'home');
						response.end('success');
					}
				}
			});
		} else {
			response.end('Error: Authorization Required!');
		}
	});
	
	// ====================( Account / Recover / Password ) ====================
	app.get(/\/account\/recover\/password\/([^\/]+)\/?/, function(request, response, mysql){
		response.head.secret_code = request.params[1];
		if(isset(response.head.secret_code)){
			response.head.page = 'recover';
			response.html();
		} else {
			response.head.page = '404';
			response.html();
			mysql.end();
		}
	});
	/*
	app.post(/\/account\/recover\/password\/([^\/]+)\/?/, function(request, response, mysql){
		request.check('new_password');
		request.check('new_password_again');
		request.check('new_password').equals(request.body.new_password_again);
		if(isset(request.params[1])){
			if(request.passed){
				mysql.accounts.update('secret_code', request.params[1], { 
					'secret_code': 0, 
					password: sha1(request.body.new_password)
				}, function(rows){
					if(rows.affectedRows){
						response.success();
					} else {
						request.error('secret_code', 'is invalid');
						response.error();
					}
				});
			} else {
				response.error();
			}
		} else {
			request.error('secret_code', 'is invalid');
			response.error();
		}
	});*/
	
	app.post('/account/recover', function(request, response, mysql){
		console.log(request.body);
		if(isset(request.body.recovery_email)){
			mysql.accounts.get('email', request.body.recovery_email, function(rows){
				if(rows && rows.length){
					var reset_code = uniqid() + '-' + uniqid() + sha1(request.body.recovery_email);
					mysql.accounts.update('id', rows[0].id, { reset_code: reset_code }, function(){
						mail.send({
							email 	 	: request.body.recovery_email,
							subject		: 'Password Reset',
							html 		: 'recover.html',
							reset_code	: reset_code,
							echo 		: response.head.echo,
							account		: rows[0]
						});
						if(events.recover){ 
							events.recover(request, response, mysql); 
						} else {
							response.success();
							mysql.end();
						}
						
					});
				} else {
					request.error('recovery_email', 'No Email Found');
					if(events.recover){ 
						events.recover(request, response, mysql); 
					} else {
						response.error();
						mysql.end();
					}
				}
			});
			
		} else {
			request.error('recovery_email', 'Email is invalid');
			if(events.recover){ 
				events.recover(request, response, mysql); 
			} else {
				response.error();
				mysql.end();
			}
		}
	});
	
	// ====================( Account / Verify ) ====================
	app.get(/\/accounts\/verify\/([^\/]+)\/?(success\/?)?/i, function(request, response, mysql){
		var key 				= request.params[1];
		var success				= request.params[2];
		response.data.title 	= 'Something went wrong';
		response.data.page 		= 'activate';
		response.data.subpage 	= 'error';
		if(isset(key)){
			// check key 
			if(!isset(success)){
				// find user by key
				mysql.accounts.get('activated', key, function(rows){
					// key accepted: activate user
					if(rows && rows[0]){
						var account = rows[0];
						account.session = Auth.createSession(account.password);
						mysql.accounts.update('activated', key, { activated: 1 }, function(){
							mysql.accounts.update('id', account.id, {session: account.session}, function(){
								if(events.verify){
									Auth.login(response, account.session);
									events.verify(request, response, mysql, account);
								} else {
									Auth.login(response, account.session, '/accounts/verify/'+key+'/success');
									mysql.end();
								}
							});
						});
					// key rejected
					} else {
						response.finish();
					}
				});	
			// success page
			} else {
				response.data.title = 'Account verified';
				response.data.page = 'verified';
				response.finish();
			}
		// key rejected
		} else {
			response.finish();
		}
	});
	return app;
};






