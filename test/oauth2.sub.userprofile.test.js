var chai = require('chai')
  , OAuth2Strategy = require('../lib/strategy')
  , util = require('util');


function MockOAuth2Strategy(options, verify) {
  OAuth2Strategy.call(this, options, verify);
}
util.inherits(MockOAuth2Strategy, OAuth2Strategy);

MockOAuth2Strategy.prototype.userProfile = function(accessToken, done) {
  if (accessToken == '2YotnFZFEjr1zCsicMWpAA') {
    return done(null, { username: 'jaredhanson', location: 'Oakland, CA' });
  }
  return done(new Error('failed to load user profile'));
}


describe('OAuth2Strategy', function() {
    
  describe('subclass that overrides userProfile function', function() {
    
    describe('with default options', function() {
      var strategy = new MockOAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
        },
        function(accessToken, refreshToken, profile, done) {
          if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
            return done(null, { id: '1234', profile: profile }, { message: 'Hello' });
          }
          return done(null, false);
        });
  
      // inject a "mock" oauth2 instance
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (options.grant_type !== 'authorization_code') { return callback(null, 'wrong-access-token', 'wrong-refresh-token'); }
        
        if (code == 'SplxlOBeZQQYbYS6WxSbIA' && options.redirect_uri == 'https://www.example.net/auth/example/callback') {
          return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
        } else {
          return callback(null, 'wrong-access-token', 'wrong-refresh-token');
        }
      }
  
      describe('handling an authorized return request', function() {
        var user
          , info;
  
        before(function(done) {
          chai.passport.use(strategy)
            .success(function(u, i) {
              user = u;
              info = i;
              done();
            })
            .req(function(req) {
              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
            })
            .authenticate();
        });
  
        it('should supply user', function() {
          expect(user).to.be.an.object;
          expect(user.id).to.equal('1234');
        });
        
        it('should load profile', function() {
          expect(user.profile).to.not.be.undefined;
          expect(user.profile.username).to.equal('jaredhanson');
        });
  
        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Hello');
        });
      });
    
      describe('failing to load user profile', function() {
        var err;
  
        before(function(done) {
          chai.passport.use(strategy)
            .error(function(e) {
              err = e;
              done();
            })
            .req(function(req) {
              req.query = {};
              req.query.code = 'wrong-code';
            })
            .authenticate();
        });
  
        it('should error', function() {
          expect(err).to.be.an.instanceof(Error)
          expect(err.message).to.equal('failed to load user profile');
        });
      });
    });
  
  
    describe('with skip profile option set to true', function() {
      var strategy = new MockOAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          skipUserProfile: true
        },
        function(accessToken, refreshToken, profile, done) {
          if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
            return done(null, { id: '1234', profile: profile }, { message: 'Hello' });
          }
          return done(null, false);
        });
  
      // inject a "mock" oauth2 instance
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (options.grant_type !== 'authorization_code') { return callback(null, 'wrong-access-token', 'wrong-refresh-token'); }
        
        if (code == 'SplxlOBeZQQYbYS6WxSbIA' && options.redirect_uri == 'https://www.example.net/auth/example/callback') {
          callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
        } else {
          callback(null, 'wrong-access-token', 'wrong-refresh-token');
        }
      }
  
      describe('handling an authorized return request', function() {
        var user
          , info;
  
        before(function(done) {
          chai.passport.use(strategy)
            .success(function(u, i) {
              user = u;
              info = i;
              done();
            })
            .req(function(req) {
              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
            })
            .authenticate();
        });
  
        it('should supply user', function() {
          expect(user).to.be.an.object;
          expect(user.id).to.equal('1234');
        });
        
        it('should not load profile', function() {
          expect(user.profile).to.be.undefined;
        });
  
        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Hello');
        });
      });
    });
  
  
    describe('with skip profile function that synchronously returns false', function() {
      var strategy = new MockOAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          skipUserProfile: function() {
            return false;
          }
        },
        function(accessToken, refreshToken, profile, done) {
          if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
            return done(null, { id: '1234', profile: profile }, { message: 'Hello' });
          }
          return done(null, false);
        });
  
      // inject a "mock" oauth2 instance
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (options.grant_type !== 'authorization_code') { return callback(null, 'wrong-access-token', 'wrong-refresh-token'); }
        
        if (code == 'SplxlOBeZQQYbYS6WxSbIA' && options.redirect_uri == 'https://www.example.net/auth/example/callback') {
          callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
        } else {
          callback(null, 'wrong-access-token', 'wrong-refresh-token');
        }
      }
  
      describe('handling an authorized return request', function() {
        var user
          , info;
  
        before(function(done) {
          chai.passport.use(strategy)
            .success(function(u, i) {
              user = u;
              info = i;
              done();
            })
            .req(function(req) {
              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
            })
            .authenticate();
        });
  
        it('should supply user', function() {
          expect(user).to.be.an.object;
          expect(user.id).to.equal('1234');
        });
        
        it('should load profile', function() {
          expect(user.profile).to.not.be.undefined;
          expect(user.profile.username).to.equal('jaredhanson');
        });
  
        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Hello');
        });
      });
    });
  
  
    describe('with skip profile function that synchronously returns true', function() {
      var strategy = new MockOAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          skipUserProfile: function() {
            return true;
          }
        },
        function(accessToken, refreshToken, profile, done) {
          if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
            return done(null, { id: '1234', profile: profile }, { message: 'Hello' });
          }
          return done(null, false);
        });
  
      // inject a "mock" oauth2 instance
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (options.grant_type !== 'authorization_code') { return callback(null, 'wrong-access-token', 'wrong-refresh-token'); }
        
        if (code == 'SplxlOBeZQQYbYS6WxSbIA' && options.redirect_uri == 'https://www.example.net/auth/example/callback') {
          callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
        } else {
          callback(null, 'wrong-access-token', 'wrong-refresh-token');
        }
      }
  
      describe('handling an authorized return request', function() {
        var user
          , info;
  
        before(function(done) {
          chai.passport.use(strategy)
            .success(function(u, i) {
              user = u;
              info = i;
              done();
            })
            .req(function(req) {
              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
            })
            .authenticate();
        });
  
        it('should supply user', function() {
          expect(user).to.be.an.object;
          expect(user.id).to.equal('1234');
        });
        
        it('should not load profile', function() {
          expect(user.profile).to.be.undefined;
        });
  
        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Hello');
        });
      });
    });
  
  
    describe('with skip profile function that asynchronously returns false', function() {
      var strategy = new MockOAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          skipUserProfile: function(accessToken, done) {
            if (accessToken == '2YotnFZFEjr1zCsicMWpAA') { return done(null, false); }
            done(null, true);
          }
        },
        function(accessToken, refreshToken, profile, done) {
          if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
            return done(null, { id: '1234', profile: profile }, { message: 'Hello' });
          }
          return done(null, false);
        });
  
      // inject a "mock" oauth2 instance
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (options.grant_type !== 'authorization_code') { return callback(null, 'wrong-access-token', 'wrong-refresh-token'); }
        
        if (code == 'SplxlOBeZQQYbYS6WxSbIA' && options.redirect_uri == 'https://www.example.net/auth/example/callback') {
          callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
        } else {
          callback(null, 'wrong-access-token', 'wrong-refresh-token');
        }
      }
  
      describe('handling an authorized return request', function() {
        var user
          , info;
  
        before(function(done) {
          chai.passport.use(strategy)
            .success(function(u, i) {
              user = u;
              info = i;
              done();
            })
            .req(function(req) {
              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
            })
            .authenticate();
        });
  
        it('should supply user', function() {
          expect(user).to.be.an.object;
          expect(user.id).to.equal('1234');
        });
        
        it('should load profile', function() {
          expect(user.profile).to.not.be.undefined;
          expect(user.profile.username).to.equal('jaredhanson');
        });
  
        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Hello');
        });
      });
    });
  
  
    describe('with skip profile function that asynchronously returns true', function() {
      var strategy = new MockOAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          skipUserProfile: function(accessToken, done) {
            if (accessToken == '2YotnFZFEjr1zCsicMWpAA') { return done(null, true); }
            done(null, false);
          }
        },
        function(accessToken, refreshToken, profile, done) {
          if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
            return done(null, { id: '1234', profile: profile }, { message: 'Hello' });
          }
          return done(null, false);
        });
  
      // inject a "mock" oauth2 instance
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (options.grant_type !== 'authorization_code') { return callback(null, 'wrong-access-token', 'wrong-refresh-token'); }
        
        if (code == 'SplxlOBeZQQYbYS6WxSbIA' && options.redirect_uri == 'https://www.example.net/auth/example/callback') {
          callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
        } else {
          callback(null, 'wrong-access-token', 'wrong-refresh-token');
        }
      }
  
      describe('handling an authorized return request', function() {
        var user
          , info;
  
        before(function(done) {
          chai.passport.use(strategy)
            .success(function(u, i) {
              user = u;
              info = i;
              done();
            })
            .req(function(req) {
              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
            })
            .authenticate();
        });
  
        it('should supply user', function() {
          expect(user).to.be.an.object;
          expect(user.id).to.equal('1234');
        });
        
        it('should not load profile', function() {
          expect(user.profile).to.be.undefined;
        });
  
        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Hello');
        });
      });
    });
  
  });
  
});
