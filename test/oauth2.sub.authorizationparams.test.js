var chai = require('chai')
  , OAuth2Strategy = require('../lib/strategy')
  , util = require('util');


function MockOAuth2Strategy(options, verify) {
  OAuth2Strategy.call(this, options, verify);
}
util.inherits(MockOAuth2Strategy, OAuth2Strategy);

MockOAuth2Strategy.prototype.authorizationParams = function(options) {
  return { prompt: options.prompt };
}


describe('OAuth2Strategy', function() {
    
  describe('subclass that overrides authorizationParams function', function() {
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
      if (code == 'SplxlOBeZQQYbYS6WxSbIA' && options.redirect_uri == 'https://www.example.net/auth/example/callback') {
        callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
      } else {
        callback(null, 'wrong-access-token', 'wrong-refresh-token');
      }
    }
    
  
    describe('handling a request to be redirected for authorization with prompt', function() {
      var url;
  
      before(function(done) {
        chai.passport.use(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
          })
          .authenticate({ prompt: 'mobile' });
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth2/authorize?prompt=mobile&response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123');
      });
    });
    
    describe('handling a request to be redirected for authorization with scope and prompt', function() {
      var url;
  
      before(function(done) {
        chai.passport.use(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
          })
          .authenticate({ scope: 'email', prompt: 'mobile' });
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth2/authorize?prompt=mobile&response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&scope=email&client_id=ABC123');
      });
    });
  });
  
});
