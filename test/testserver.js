var express = require('express');
var passport = require('passport');
var bcrypt = require('bcrypt');
var ApiFactory = require('../ApiFactory');

var app = express();

app.use(passport.initialize());

app.get('/', function(req, res) {
	res.send('hi');
});

var users = [
	{
		id: 3,
		name: 'desmond',
		password: bcrypt.hashSync('password', 10),
		tokens: []
	}
];

function findUserByUsername(username, fn) {
	if (!username) {
		return fn(null, null);
	}
	var res = users.filter(function(u){return u.name === username});
	return fn(null, res.length ? res[0] : null);
}


var api = ApiFactory({
	secret: 'foobar',
	userQuery: findUserByUsername	
});
api.get('/', function(req, res) {
	res.send('api');
})
app.use('/api', api);

module.exports = app;
