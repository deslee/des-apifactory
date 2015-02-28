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

	router.use(passport.initialize());
	router.use(methodOverride('X-HTTP-Method-Override'));
	router.use(bodyParser.json());
	router.use(bodyParser.urlencoded({extended: false}));

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
					var userHasToken = user.tokens.indexOf(token) !== -1
					if (!userHasToken) {
						return done(null, false);
					}
					return done(null, user);
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
			var username = req.body.username,
				password = req.body.password;

			var user = req.user;
			var token = jwt.sign({id: user.id, name: user.name}, secret);
			user.tokens.push(token);
			res.send(token);
		}
	);

	router.delete(
		'/token',
		passport.authenticate('bearer', {session: false}),
		function(req, res) {
			var token = req.get('Authorization').split(' ')[1];
			var idx = req.user.tokens.indexOf(token);
			if (idx !== -1) {
				req.user.tokens.splice(idx, 1);
				res.sendStatus(200);
			}
			else {
				res.sendStatus(401);
			}
		}
	);

	return router;
}
