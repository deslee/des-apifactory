var express = require('express'),
	Router = express.Router,
	bcrypt = require('bcrypt'),
	jwt = require('jsonwebtoken'),
	passport = require('passport'),
	methodOverride = require('method-override'),
	bodyParser = require('body-parser'),
	BearerStrategy = require('passport-http-bearer').Strategy,
	LocalStrategy = require('passport-local')

module.exports = function(options) {
	var router = Router();
	var secret = options.secret;
	var findUserByUsername = options.userQuery;

	var tokenExpiration = options.tokenExpirationMinutes || 60;

	router.use(passport.initialize());
	router.use(methodOverride('X-HTTP-Method-Override'));
	router.use(bodyParser.json());
	router.use(bodyParser.urlencoded({extended: false}));
	
	var token_whitelist = {}

	passport.use(new BearerStrategy(
		{},
		function(token, done) {
			jwt.verify(token, secret, function(err, auth){
				if (err) {
					return done(err);
				}
				if (!auth) {
					return done(null, false);
				}
				findUserByUsername(auth.name, function(err, user) {
					if (err) {
						return done(err);
					}
					if (!user) {
						return done(null, false);
					}
					// check token validation
					if (!token_whitelist[token]) {
						return done(null, false);
					}
					return done(null, user, {token: token});
				});	

			});		
		}
	));

	passport.use(new LocalStrategy(
		{},
		function(username, password, done){
			findUserByUsername(username, function(err, user) {
				if (err) {
					return done(err);
				}
				if (!user) {
					return done(null, false);
				}
				bcrypt.compare(
					password,
					user.password,
					function(err, match) {
						if (err) {
							return done(err);
						}
						if (!match) {
							return done(null, false);
						}

						return done(null, user);
					}
				)
				
			});
		}
	));

	router.post(
		'/token', 
		passport.authenticate('local', {session: false}),
		function(req, res) {
			var user = req.user;
			
			var token = jwt.sign({name: user.name}, secret, {expiresInMinutes: req.body.tokenExpiration || tokenExpiration});
			token_whitelist[token] = user.name;
			res.send(token);
		}
	);

	router.delete(
		'/token',
		passport.authenticate('bearer', {session: false}),
		function(req, res) {
			if (delete token_whitelist[req.authInfo.token]) {
				res.sendStatus(200);
			}
			else {
				req.sendStatus(401);
			}
		}
	);

	router.get(
		'/test',
		passport.authenticate('bearer', {session: false}),
		function(req, res) {
			res.send(req.user.name);
		}
	);
	return router;
}
