var chai = require('chai')
  , OAuth2Strategy = require('../lib/strategy')
  , InternalOAuthError = require('../lib/errors/internaloautherror');


describe('OAuth2Strategy', function() {
    
  describe('that encounters an error obtaining an access token', function() {
    
    var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, params, profile, done) {
        if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
          return done(null, { id: '1234' }, { message: 'Hello' });
        }
        return done(null, false);
      });
  
    // inject a "mock" oauth2 instance
    strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
      return callback(new Error('something went wrong'));
    }
  
    describe('handling an authorized return request', function() {
      var err;
  
      before(function(done) {
        chai.passport(strategy)
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
        expect(err.oauthError.message).to.equal('something went wrong');
      });
    });
  });
  
  describe('that encounters an error during verification', function() {
    
    var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, params, profile, done) {
        return done(new Error('something went wrong'));
      });
  
    // inject a "mock" oauth2 instance
    strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
      if (code == 'SplxlOBeZQQYbYS6WxSbIA' && options.grant_type == 'authorization_code') {
        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
      } else {
        return callback(null, 'wrong-access-token', 'wrong-refresh-token');
      }
    }
  
    describe('handling an authorized return request', function() {
      var err;
  
      before(function(done) {
        chai.passport(strategy)
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
        expect(err.message).to.equal('something went wrong');
      });
    });
  });
  
});
