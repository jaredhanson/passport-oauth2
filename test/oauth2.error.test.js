var chai = require('chai')
  , OAuth2Strategy = require('../lib/strategy')
  , TokenError = require('../lib/errors/tokenerror')
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
        expect(err.oauthError.message).to.equal('something went wrong');
      });
    });
  });
  
  describe('that encounters a node-oauth object literal error with OAuth-compatible body obtaining an access token', function() {
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
      return callback({ statusCode: 400, data: '{"error":"invalid_grant","error_description":"The provided value for the input parameter \'code\' is not valid."} '});
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
        expect(err).to.be.an.instanceof(TokenError)
        expect(err.message).to.equal('The provided value for the input parameter \'code\' is not valid.');
        expect(err.code).to.equal('invalid_grant');
        expect(err.oauthError).to.be.undefined;
      });
    });
  });
  
  describe('that encounters a node-oauth object literal error with nearly-OAuth-compatible body obtaining an access token', function() {
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
      return callback({ statusCode: 400, data: '{"error_code":"invalid_grant"}'});
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
        expect(err.oauthError.statusCode).to.equal(400);
        expect(err.oauthError.data).to.equal('{"error_code":"invalid_grant"}');
      });
    });
  });
  
  describe('that encounters a node-oauth object literal error with non-OAuth-compatible body obtaining an access token', function() {
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
      return callback({ statusCode: 500, data: 'Something went wrong'});
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
        expect(err.oauthError.data).to.equal('Something went wrong');
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
        expect(err.message).to.equal('something went wrong');
      });
    });
  });
  
  describe('that encounters a thrown error during verification', function() {
    
    var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, params, profile, done) {
        throw new Error('something was thrown');
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
        expect(err.message).to.equal('something was thrown');
      });
    });
  });
  
});
