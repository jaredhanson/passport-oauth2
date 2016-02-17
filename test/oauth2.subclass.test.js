var OAuth2Strategy = require('../lib/strategy')
  , AuthorizationError = require('../lib/errors/authorizationerror')
  , InternalOAuthError = require('../lib/errors/internaloautherror')
  , chai = require('chai')
  , util = require('util');


describe('OAuth2Strategy subclass', function() {
  
  describe('that overrides authorizationParams', function() {
    function FooOAuth2Strategy(options, verify) {
      OAuth2Strategy.call(this, options, verify);
    }
    util.inherits(FooOAuth2Strategy, OAuth2Strategy);

    FooOAuth2Strategy.prototype.authorizationParams = function(options) {
      return { prompt: options.prompt };
    }
    
    
    describe('issuing authorization request that redirects to service provider', function() {
      var strategy = new FooOAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
        if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
        
        return done(null, { id: '1234' }, { message: 'Hello' });
      });
    
  
      describe('with prompt', function() {
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
      }); // with prompt
    
      describe('with scope and prompt', function() {
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
      }); // with scope and prompt
    
    }); // issuing authorization request that redirects to service provider
    
  }); // that overrides authorizationParams
  
  
  describe('that overrides tokenParams', function() {
    function FooOAuth2Strategy(options, verify) {
      OAuth2Strategy.call(this, options, verify);
    }
    util.inherits(FooOAuth2Strategy, OAuth2Strategy);

    FooOAuth2Strategy.prototype.tokenParams = function(options) {
      return { type: options.type };
    }
    
    
    describe('processing response to authorization request that was approved', function() {
      var strategy = new FooOAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
        if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
        
        return done(null, { id: '1234' }, { message: 'Hello' });
      });
      
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
        if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
        if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }
        if (options.type !== 'web_server') { return callback(new Error('incorrect options.type argument')); }
        
        callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
      }
      
      
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
          .authenticate({ type: 'web_server' });
      });

      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
    }); // processing response to authorization request that was approved
    
  }); // that overrides tokenParams
  
  
  describe('that overrides parseErrorResponse', function() {
    function FooOAuth2Strategy(options, verify) {
      OAuth2Strategy.call(this, options, verify);
    }
    util.inherits(FooOAuth2Strategy, OAuth2Strategy);

    FooOAuth2Strategy.prototype.parseErrorResponse = function(body, status) {
      if (status === 500) { throw new Error('something went horribly wrong'); }
  
      var e = new Error('Custom OAuth error');
      e.body = body;
      e.status = status;
      return e;
    }
    
    
    describe('and supplies error', function() {
      var strategy = new FooOAuth2Strategy({
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
      
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        return callback({ statusCode: 400, data: 'Invalid code' });
      }
    
    
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
    }); // and supplies error
    
    describe('and throws exception', function() {
      var strategy = new FooOAuth2Strategy({
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
      
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        return callback({ statusCode: 500, data: 'Invalid code' });
      }
    
    
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
    }); // and throws exception
    
  }); // that overrides parseErrorResponse
  
});
