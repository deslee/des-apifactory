var assert = require("assert")
var request = require('supertest');
var app = require('./testserver');

describe('Server', function(){

	it('should have a default route', function(done) {
		request(app)
			.get('/')
			.expect(200)
			.expect('hi')
			.end(done)
	});

	describe('Token based authentication', function() {
		var agent = request.agent(app);

		it('should return bad request', function(done) {
			agent
				.post('/api/token')
				.expect(400)
				.end(done)
		});
		
		it('should return unauthorized', function(done) {
			agent
				.post('/api/token')
				.send({username: 'foo', password: 'bar'})
				.expect(401)
				.end(done)
		});

		it('should not be able to delete a token', function(done) {
			agent.delete('/api/token')
				.expect(401)
				.end(done)
		})

		describe('user authentication', function() {
			var token;
			before('should return a token', function(done) {
				agent
					.post('/api/token')
					.send({username: 'desmond', password: 'password'})
					.expect(200)
					.end(function(err, response) {
						token = response.text;
						done(err);
					})
			});

			it('unauthorized without token', function(done) {
				agent
					.get('/api/test')
					.expect(401)
					.end(done);
			});

			it('authorized with token', function(done) {
				agent
					.get('/api/test')
					.set('Authorization', 'Bearer ' + token)
					.expect(200)
					.end(done);
			});
	
			it('should be able to delete a token', function(done) {
				agent.delete('/api/token')
					.expect(200)
					.set('Authorization', 'Bearer ' + token)
					.end(done)
			})

			it('should not be able to delete a token after deleting one', function(done) {
				agent.delete('/api/token')
					.expect(401)
					.set('Authorization', 'Bearer ' + token)
					.end(done)
			});
		});
	});
})
