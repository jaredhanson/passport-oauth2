var chai = require('chai')
  , OAuth2Strategy = require('../lib/strategy');


describe('OAuth2Strategy', function() {
  
  describe('failing verification with additional information', function() {
    var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, profile, done) {
        return done(null, false, { message: 'Invite required' });
      });
  
    // inject a "mock" oauth2 instance
    strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
      if (options.grant_type !== 'authorization_code') { return callback(null, 'wrong-access-token', 'wrong-refresh-token'); }
      
      if (code == 'SplxlOBeZQQYbYS6WxSbIA') {
        callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example', expires_in: 3600, example_parameter: 'example_value' });
      } else {
        callback(null, 'wrong-access-token', 'wrong-refresh-token');
      }
    }
  
    describe('handling a return request', function() {
      var info;
  
      before(function(done) {
        chai.passport.use(strategy)
          .fail(function(i) {
            info = i;
            done();
          })
          .req(function(req) {
            req.query = {};
            req.query.code = 'wrong-code';
          })
          .authenticate();
      });
  
      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Invite required');
      });
    });
  });
  
});
