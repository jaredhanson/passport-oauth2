var chai = require('chai')
  , OAuth2Strategy = require('../lib/strategy')
  , util = require('util')
  , InternalOAuthError = require('../lib/errors/internaloautherror')


function MockOAuth2Strategy(options, verify) {
  OAuth2Strategy.call(this, options, verify);
}
util.inherits(MockOAuth2Strategy, OAuth2Strategy);

MockOAuth2Strategy.prototype.parseErrorResponse = function(body, status) {
  if (status !== 400) { throw new Error('Whoops'); }
  
  var e = new Error('Custom OAuth error');
  e.body = body;
  e.status = status;
  return e;
}


describe('OAuth2Strategy', function() {
    
  describe('subclass that overrides parseErrorResponse function', function() {
    
    describe('parsing an error from token endpoint', function() {
      var strategy = new MockOAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
        },
        function(accessToken, refreshToken, profile, done) {
          if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
            return done(null, { id: '1234' }, { message: 'Hello' });
          }
          return done(null, false);
        });
  
      // inject a "mock" oauth2 instance
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        return callback({ statusCode: 400, data: 'Invalid code' });
      }
    
      describe('handling an authorized return request', function() {
        var err;
  
        before(function(done) {
          chai.passport.use(strategy)
            .error(function(e) {
              err = e;
              done();
            })
            .req(function(req) {
              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
            })
            .authenticate();
        });
  
        it('should error', function() {
          expect(err).to.be.an.instanceof(Error);
          expect(err.message).to.equal('Custom OAuth error');
          expect(err.body).to.equal('Invalid code');
          expect(err.status).to.equal(400);
        });
      });
    });
  });
  
  describe('subclass that overrides parseErrorResponse function and throws', function() {
    
    describe('parsing an error from token endpoint', function() {
      var strategy = new MockOAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
        },
        function(accessToken, refreshToken, profile, done) {
          if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
            return done(null, { id: '1234' }, { message: 'Hello' });
          }
          return done(null, false);
        });
  
      // inject a "mock" oauth2 instance
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        return callback({ statusCode: 500, data: 'Invalid code' });
      }
    
      describe('handling an authorized return request', function() {
        var err;
  
        before(function(done) {
          chai.passport.use(strategy)
            .error(function(e) {
              err = e;
              done();
            })
            .req(function(req) {
              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
            })
            .authenticate();
        });
  
        it('should error', function() {
          expect(err).to.be.an.instanceof(InternalOAuthError)
          expect(err.message).to.equal('Failed to obtain access token');
          expect(err.oauthError.statusCode).to.equal(500);
          expect(err.oauthError.data).to.equal('Invalid code');
        });
      });
    });
  });
  
});
