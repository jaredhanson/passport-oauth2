var chai = require('chai')
  , OAuth2Strategy = require('../lib/strategy')
  , AuthorizationError = require('../lib/errors/authorizationerror');


describe('OAuth2Strategy', function() {
    
  var strategy = new OAuth2Strategy({
      authorizationURL: 'https://www.example.com/oauth2/authorize',
      tokenURL: 'https://www.example.com/oauth2/token',
      clientID: 'ABC123',
      clientSecret: 'secret',
      callbackURL: 'https://www.example.net/auth/example/callback',
    },
    function(accessToken, refreshToken, profile, done) {
      if (Object.keys(profile).length !== 0) { return done(null, false); }
      
      if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
        return done(null, { id: '1234' }, { message: 'Hello' });
      } else if (accessToken == '2YotnFZFEjr1zCsicMWpAA+ALT1' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA+ALT1') { 
        return done(null, { id: '2234' }, { message: 'Hello' });
      } else if (accessToken == '2YotnFZFEjr1zCsicMWpAA+ALT2' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA+ALT2') { 
        return done(null, { id: '3234' }, { message: 'Hello' });
      }
      return done(null, false);
    });
  
  // inject a "mock" oauth2 instance
  strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
    if (options.grant_type !== 'authorization_code') { return callback(null, 'wrong-access-token', 'wrong-refresh-token'); }
    
    if (code == 'SplxlOBeZQQYbYS6WxSbIA' && options.redirect_uri == 'https://www.example.net/auth/example/callback') {
      return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
    } else if (code == 'SplxlOBeZQQYbYS6WxSbIA+ALT1' && options.redirect_uri == 'https://www.example.net/auth/example/callback/alt1') {
      return callback(null, '2YotnFZFEjr1zCsicMWpAA+ALT1', 'tGzv3JOkF0XG5Qx2TlKWIA+ALT1', { token_type: 'example' });
    } else if (code == 'SplxlOBeZQQYbYS6WxSbIA+ALT2' && options.redirect_uri == 'https://www.example.net/auth/example/callback/alt2') {
      return callback(null, '2YotnFZFEjr1zCsicMWpAA+ALT2', 'tGzv3JOkF0XG5Qx2TlKWIA+ALT2', { token_type: 'example' });
    } else {
      return callback(null, 'wrong-access-token', 'wrong-refresh-token');
    }
  }
  
  describe('handling a return request in which authorization has been denied by the user without description', function() {
    var info;
  
    before(function(done) {
      chai.passport.use(strategy)
        .fail(function(i) {
          info = i;
          done();
        })
        .req(function(req) {
          req.query = {};
          req.query.error = 'access_denied';
        })
        .authenticate();
    });
  
    it('should fail without message', function() {
      expect(info).to.not.be.undefined;
      expect(info.message).to.be.undefined;
    });
  });
  
  describe('handling a return request in which authorization has been denied by the user with description', function() {
    var info;
  
    before(function(done) {
      chai.passport.use(strategy)
        .fail(function(i) {
          info = i;
          done();
        })
        .req(function(req) {
          req.query = {};
          req.query.error = 'access_denied';
          req.query.error_description = 'Why oh why?';
        })
        .authenticate();
    });
  
    it('should fail with message', function() {
      expect(info).to.not.be.undefined;
      expect(info.message).to.equal('Why oh why?');
    });
  });
  
  describe('handling a return request that indicates server error without description', function() {
    var err;
  
    before(function(done) {
      chai.passport.use(strategy)
        .error(function(e) {
          err = e;
          done();
        })
        .req(function(req) {
          req.query = {};
          req.query.error = 'invalid_scope';
        })
        .authenticate();
    });
  
    it('should error', function() {
      expect(err).to.be.an.instanceof(AuthorizationError)
      expect(err.message).to.be.undefined;
      expect(err.code).to.equal('invalid_scope');
      expect(err.uri).to.be.undefined;
      expect(err.status).to.equal(500);
    });
  });
  
  describe('handling a return request that indicates server error with description', function() {
    var err;
  
    before(function(done) {
      chai.passport.use(strategy)
        .error(function(e) {
          err = e;
          done();
        })
        .req(function(req) {
          req.query = {};
          req.query.error = 'invalid_scope';
          req.query.error_description = 'The scope is invalid';
        })
        .authenticate();
    });
  
    it('should error', function() {
      expect(err).to.be.an.instanceof(AuthorizationError)
      expect(err.message).to.equal('The scope is invalid');
      expect(err.code).to.equal('invalid_scope');
      expect(err.uri).to.be.undefined;
      expect(err.status).to.equal(500);
    });
  });
  
  describe('handling a return request that indicates server error with description and link', function() {
    var err;
  
    before(function(done) {
      chai.passport.use(strategy)
        .error(function(e) {
          err = e;
          done();
        })
        .req(function(req) {
          req.query = {};
          req.query.error = 'invalid_scope';
          req.query.error_description = 'The scope is invalid';
          req.query.error_uri = 'http://www.example.com/oauth2/help';
        })
        .authenticate();
    });
  
    it('should error', function() {
      expect(err).to.be.an.instanceof(AuthorizationError)
      expect(err.message).to.equal('The scope is invalid');
      expect(err.uri).to.equal('http://www.example.com/oauth2/help');
      expect(err.status).to.equal(500);
    });
  });
  
  describe('handling a return request that fails verification', function() {
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
  
    it('should not supply info', function() {
      expect(info).to.be.undefined;
    });
  });
  
});
