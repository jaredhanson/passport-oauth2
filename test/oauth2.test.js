var OAuth2Strategy = require('../lib/strategy')
  , AuthorizationError = require('../lib/errors/authorizationerror')
  , TokenError = require('../lib/errors/tokenerror')
  , InternalOAuthError = require('../lib/errors/internaloautherror')
  , chai = require('chai');


describe('OAuth2Strategy', function() {
  
  describe('constructed', function() {
    
    describe('with normal options', function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret'
        }, function() {});
    
      it('should be named oauth2', function() {
        expect(strategy.name).to.equal('oauth2');
      });
    }); // with normal options
    
    describe('without a verify callback', function() {
      it('should throw', function() {
        expect(function() {
          new OAuth2Strategy({
            authorizationURL: 'https://www.example.com/oauth2/authorize',
            tokenURL: 'https://www.example.com/oauth2/token',
            clientID: 'ABC123',
            clientSecret: 'secret'
          });
        }).to.throw(TypeError, 'OAuth2Strategy requires a verify callback');
      });
    }); // without a verify callback
    
    describe('without an authorizationURL option', function() {
      it('should throw', function() {
        expect(function() {
          new OAuth2Strategy({
            tokenURL: 'https://www.example.com/oauth2/token',
            clientID: 'ABC123',
            clientSecret: 'secret'
          }, function() {});
        }).to.throw(TypeError, 'OAuth2Strategy requires a authorizationURL option');
      });
    }); // without an authorizationURL option
    
    describe('without a tokenURL option', function() {
      it('should throw', function() {
        expect(function() {
          new OAuth2Strategy({
            authorizationURL: 'https://www.example.com/oauth2/authorize',
            clientID: 'ABC123',
            clientSecret: 'secret'
          }, function() {});
        }).to.throw(TypeError, 'OAuth2Strategy requires a tokenURL option');
      });
    }); // without a tokenURL option
    
    describe('without a clientID option', function() {
      it('should throw', function() {
        expect(function() {
          new OAuth2Strategy({
            authorizationURL: 'https://www.example.com/oauth2/authorize',
            tokenURL: 'https://www.example.com/oauth2/token',
            clientSecret: 'secret'
          }, function() {});
        }).to.throw(TypeError, 'OAuth2Strategy requires a clientID option');
      });
    }); // without a clientID option
    
    describe('without a clientSecret option', function() {
      it('should not throw', function() {
        expect(function() {
          new OAuth2Strategy({
            authorizationURL: 'https://www.example.com/oauth2/authorize',
            tokenURL: 'https://www.example.com/oauth2/token',
            clientID: 'ABC123'
          }, function() {});
        }).to.not.throw();
      });
    }); // without a clientSecret option
    
    describe('with only a verify callback', function() {
      it('should throw', function() {
        expect(function() {
          new OAuth2Strategy(function() {});
        }).to.throw(TypeError, 'OAuth2Strategy requires a authorizationURL option');
      });
    }); // with only a verify callback
    
  }); // constructed
  
  
  describe('issuing authorization request', function() {
    
    describe('that redirects to service provider without redirect URI', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret'
      },
      function(accessToken, refreshToken, profile, done) {});
      
      
      var url;
  
      before(function(done) {
        chai.passport.use(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
          })
          .authenticate();
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&client_id=ABC123');
      });
    }); // that redirects to service provider without redirect URI
    
    describe('that redirects to service provider with redirect URI', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, profile, done) {});
      
      
      var url;
  
      before(function(done) {
        chai.passport.use(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
          })
          .authenticate();
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123');
      });
    }); // that redirects to service provider with redirect URI
    
    describe('that redirects to service provider with redirect URI and scope', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        scope: 'email'
      },
      function(accessToken, refreshToken, profile, done) {});
      
      
      var url;
  
      before(function(done) {
        chai.passport.use(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
          })
          .authenticate();
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&scope=email&client_id=ABC123');
      });
    }); // that redirects to service provider with redirect URI and scope
    
    describe('that redirects to service provider with scope option', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, profile, done) {});
      
      
      var url;
  
      before(function(done) {
        chai.passport.use(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
          })
          .authenticate({ scope: 'email' });
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&scope=email&client_id=ABC123');
      });
    }); // that redirects to service provider with scope option
    
    describe('that redirects to service provider with scope option as array', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, profile, done) {});
      
      
      var url;
  
      before(function(done) {
        chai.passport.use(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
          })
          .authenticate({ scope: ['permission_1', 'permission_2' ] });
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&scope=permission_1%20permission_2&client_id=ABC123');
      });
    }); // that redirects to service provider with scope option as array
    
    describe('that redirects to service provider with scope option as array using non-standard separator', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        scopeSeparator: ','
      },
      function(accessToken, refreshToken, profile, done) {});
      
      
      var url;
  
      before(function(done) {
        chai.passport.use(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
          })
          .authenticate({ scope: ['permission_1', 'permission_2' ] });
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&scope=permission_1%2Cpermission_2&client_id=ABC123');
      });
    }); // that redirects to service provider with scope option as array using non-standard separator
    
    describe('that redirects to service provider with state option', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, profile, done) {});
      
      
      var url;
  
      before(function(done) {
        chai.passport.use(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
          })
          .authenticate({ state: 'foo123' });
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&state=foo123&client_id=ABC123');
      });
    }); // that redirects to service provider with state option
    
    describe('that redirects to service provider with redirect URI option', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, profile, done) {});
      
      
      var url;
  
      before(function(done) {
        chai.passport.use(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
          })
          .authenticate({ callbackURL: 'https://www.example.net/auth/example/callback/alt1' });
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback%2Falt1&client_id=ABC123');
      });
    }); // that redirects to service provider with redirect URI option
    
    describe('that redirects to service provider with relative redirect URI option', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, profile, done) {});
      
      
      var url;
  
      before(function(done) {
        chai.passport.use(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
            req.url = '/auth/example/callback/alt2';
            req.headers.host = 'www.example.net';
            req.connection = { encrypted: true };
          })
          .authenticate({ callbackURL: '/auth/example/callback/alt2' });
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback%2Falt2&client_id=ABC123');
      });
    }); // that redirects to service provider with relative redirect URI option
    
  }); // issuing authorization request
  
  
  describe('processing response to authorization request', function() {
    
    describe('that was approved without redirect URI', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret'
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
        if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
        if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
        if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }
    
        return done(null, { id: '1234' }, { message: 'Hello' });
      });
      
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
        if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
        if (options.redirect_uri !== undefined) { return callback(new Error('incorrect options.redirect_uri argument')); }
        
        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
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
          .authenticate();
      });

      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
    }); // that was approved without redirect URI
    
    describe('that was approved with redirect URI', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
        if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
        if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
        if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }
    
        return done(null, { id: '1234' }, { message: 'Hello' });
      });
      
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
        if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
        if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }
        
        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
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
          .authenticate();
      });

      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
    }); // that was approved with redirect URI
    
    describe('that was approved with redirect URI option', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
        if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
        if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
        if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }
    
        return done(null, { id: '1234' }, { message: 'Hello' });
      });
      
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
        if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
        if (options.redirect_uri !== 'https://www.example.net/auth/example/callback/alt1') { return callback(new Error('incorrect options.redirect_uri argument')); }
        
        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
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
          .authenticate({ callbackURL: 'https://www.example.net/auth/example/callback/alt1' });
      });

      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
    }); // that was approved with redirect URI option
    
    describe('that was approved with relative redirect URI option', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
        if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
        if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
        if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }
    
        return done(null, { id: '1234' }, { message: 'Hello' });
      });
      
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
        if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
        if (options.redirect_uri !== 'https://www.example.net/auth/example/callback/alt2') { return callback(new Error('incorrect options.redirect_uri argument')); }
        
        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
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
            req.url = '/auth/example/callback/alt2';
            req.headers.host = 'www.example.net';
            req.query = {};
            req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
            req.connection = { encrypted: true };
          })
          .authenticate({ callbackURL: '/auth/example/callback/alt2' });
      });

      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
    }); // that was approved with relative redirect URI option
    
    describe('that was approved using verify callback that accepts params', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, params, profile, done) {
        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
        if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
        if (params.example_parameter !== 'example_value') { return done(new Error('incorrect params argument')); }
        if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
        if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }
    
        return done(null, { id: '1234' }, { message: 'Hello' });
      });
      
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
        if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
        if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }
        
        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example', expires_in: 3600, example_parameter: 'example_value' });
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
          .authenticate();
      });

      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
    }); // that was approved using verify callback that accepts params
    
    describe('that was approved using verify callback, in passReqToCallback mode', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        passReqToCallback: true
      },
      function(req, accessToken, refreshToken, profile, done) {
        if (req.method != 'GET') { return done(new Error('incorrect req argument')); }
        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
        if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
        if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
        if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }
    
        return done(null, { id: '1234' }, { message: 'Hello' });
      });
      
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
        if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
        if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }
        
        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example', expires_in: 3600 });
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
          .authenticate();
      });

      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
    }); // that was approved using verify callback, in passReqToCallback mode
    
    describe('that was approved using verify callback that accepts params, in passReqToCallback mode', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        passReqToCallback: true
      },
      function(req, accessToken, refreshToken, params, profile, done) {
        if (req.method != 'GET') { return done(new Error('incorrect req argument')); }
        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
        if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
        if (params.example_parameter !== 'example_value') { return done(new Error('incorrect params argument')); }
        if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
        if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }
    
        return done(null, { id: '1234' }, { message: 'Hello' });
      });
      
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
        if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
        if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }
        
        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example', expires_in: 3600, example_parameter: 'example_value' });
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
          .authenticate();
      });

      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
    }); // that was approved using verify callback that accepts params, in passReqToCallback mode
    
    describe('that fails due to verify callback supplying false', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, profile, done) {
        return done(null, false);
      });
      
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
        if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
        if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }
        
        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
      }
      
      
      var info;

      before(function(done) {
        chai.passport.use(strategy)
          .fail(function(i) {
            info = i;
            done();
          })
          .req(function(req) {
            req.query = {};
            req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
          })
          .authenticate();
      });

      it('should not supply info', function() {
        expect(info).to.be.undefined;
      });
    }); // that fails due to verify callback supplying false
    
    describe('that fails due to verify callback supplying false with additional info', function() {
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
      
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
        if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
        if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }
        
        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
      }
      
      
      var info;

      before(function(done) {
        chai.passport.use(strategy)
          .fail(function(i) {
            info = i;
            done();
          })
          .req(function(req) {
            req.query = {};
            req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
          })
          .authenticate();
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Invite required');
      });
    }); // that fails due to verify callback supplying false with additional info
    
    describe('that was denied', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, profile, done) {});
      
      
      var user
        , info;

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
    }); // that was denied
    
    describe('that was denied with description', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, profile, done) {});
      
      
      var user
        , info;

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
    }); // that was denied with description
    
    describe('that was returned with an error without description', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, profile, done) {});
      
      
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
    }); // that was returned with an error without description
    
    describe('that was returned with an error with description', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, profile, done) {});
      
      
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
    }); // that was returned with an error with description
    
    describe('that was returned with an error with description and link', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, profile, done) {});
      
      
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
        expect(err.code).to.equal('invalid_scope');
        expect(err.uri).to.equal('http://www.example.com/oauth2/help');
        expect(err.status).to.equal(500);
      });
    }); // that was returned with an error with description and link
    
    describe('that errors due to token request error', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, params, profile, done) {
        return done(new Error('verify callback should not be called'));
      });
  
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        return callback(new Error('something went wrong'));
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
        expect(err.oauthError.message).to.equal('something went wrong');
      });
    }); // that errors due to token request error
    
    describe('that errors due to token request error, in node-oauth object literal form with OAuth 2.0-compatible body', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, params, profile, done) {
        return done(new Error('verify callback should not be called'));
      });
  
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        return callback({ statusCode: 400, data: '{"error":"invalid_grant","error_description":"The provided value for the input parameter \'code\' is not valid."} '});
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
        expect(err).to.be.an.instanceof(TokenError)
        expect(err.message).to.equal('The provided value for the input parameter \'code\' is not valid.');
        expect(err.code).to.equal('invalid_grant');
        expect(err.oauthError).to.be.undefined;
      });
    }); // that errors due to token request error, in node-oauth object literal form with OAuth 2.0-compatible body
    
    describe('that errors due to token request error, in node-oauth object literal form with JSON body', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, params, profile, done) {
        return done(new Error('verify callback should not be called'));
      });
  
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        return callback({ statusCode: 400, data: '{"error_code":"invalid_grant"}'});
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
        expect(err.oauthError.statusCode).to.equal(400);
        expect(err.oauthError.data).to.equal('{"error_code":"invalid_grant"}');
      });
    }); // that errors due to token request error, in node-oauth object literal form with JSON body
    
    describe('that errors due to token request error, in node-oauth object literal form with text body', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, params, profile, done) {
        return done(new Error('verify callback should not be called'));
      });
  
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        return callback({ statusCode: 500, data: 'Something went wrong'});
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
        expect(err.oauthError.data).to.equal('Something went wrong');
      });
    }); // that errors due to token request error, in node-oauth object literal form with text body
    
    describe('that errors due to verify callback supplying error', function() {
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
  
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
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
        expect(err.message).to.equal('something went wrong');
      });
    }); // that errors due to verify callback supplying error
    
    describe('that errors due to verify callback throwing error', function() {
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
  
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
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
        expect(err.message).to.equal('something was thrown');
      });
    }); // that errors due to verify callback throwing error
    
  }); // processing response to authorization request
  
  
  describe('using a relative redirect URI', function() {
  
    describe('issuing authorization request', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: '/auth/example/callback',
      },
      function(accessToken, refreshToken, profile, done) {});
  
      describe('that redirects to service provider from secure connection', function() {
        var url;

        before(function(done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              url = u;
              done();
            })
            .req(function(req) {
              req.url = '/auth/example';
              req.headers.host = 'www.example.net';
              req.connection = { encrypted: true };
            })
            .authenticate();
        });

        it('should be redirected', function() {
          expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123');
        });
      }); // that redirects to service provider from secure connection
      
      describe('that redirects to service provider from insecure connection', function() {
        var url;

        before(function(done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              url = u;
              done();
            })
            .req(function(req) {
              req.url = '/auth/example';
              req.headers.host = 'www.example.net';
              req.connection = {};
            })
            .authenticate();
        });

        it('should be redirected', function() {
          expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=http%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123');
        });
      }); // that redirects to service provider from insecure connection
      
      
      describe('from behind a secure proxy', function() {
        
        describe('that is trusted by app and sets x-forwarded-proto', function() {
          var url;

          before(function(done) {
            chai.passport.use(strategy)
              .redirect(function(u) {
                url = u;
                done();
              })
              .req(function(req) {
                req.app = {
                  get: function(name) {
                    return name == 'trust proxy' ? true : false;
                  }
                }
            
                req.url = '/auth/example';
                req.headers.host = 'www.example.net';
                req.headers['x-forwarded-proto'] = 'https';
                req.connection = {};
              })
              .authenticate();
          });

          it('should be redirected', function() {
            expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123');
          });
        }); // that is trusted by app and sets x-forwarded-proto
        
        describe('that is trusted by app and sets x-forwarded-proto and x-forwarded-host', function() {
          var url;

          before(function(done) {
            chai.passport.use(strategy)
              .redirect(function(u) {
                url = u;
                done();
              })
              .req(function(req) {
                req.app = {
                  get: function(name) {
                    return name == 'trust proxy' ? true : false;
                  }
                }
            
                req.url = '/auth/example';
                req.headers.host = 'server.internal';
                req.headers['x-forwarded-proto'] = 'https';
                req.headers['x-forwarded-host'] = 'www.example.net';
                req.connection = {};
              })
              .authenticate();
          });

          it('should be redirected', function() {
            expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123');
          });
        }); // that is trusted by app and sets x-forwarded-proto and x-forwarded-host
        
        describe('that is not trusted by app and sets x-forwarded-proto', function() {
          var url;

          before(function(done) {
            chai.passport.use(strategy)
              .redirect(function(u) {
                url = u;
                done();
              })
              .req(function(req) {
                req.app = {
                  get: function(name) {
                    return name == 'trust proxy' ? false : false;
                  }
                }
            
                req.url = '/auth/example';
                req.headers.host = 'www.example.net';
                req.headers['x-forwarded-proto'] = 'https';
                req.connection = {};
              })
              .authenticate();
          });

          it('should be redirected', function() {
            expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=http%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123');
          });
        }); // that is trusted by app and sets x-forwarded-proto and x-forwarded-host
        
        describe('that is not trusted by app and sets x-forwarded-proto and x-forwarded-host', function() {
          var url;

          before(function(done) {
            chai.passport.use(strategy)
              .redirect(function(u) {
                url = u;
                done();
              })
              .req(function(req) {
                req.app = {
                  get: function(name) {
                    return name == 'trust proxy' ? false : false;
                  }
                }
            
                req.url = '/auth/example';
                req.headers.host = 'server.internal';
                req.headers['x-forwarded-proto'] = 'https';
                req.headers['x-forwarded-host'] = 'www.example.net';
                req.connection = {};
              })
              .authenticate();
          });

          it('should be redirected', function() {
            expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=http%3A%2F%2Fserver.internal%2Fauth%2Fexample%2Fcallback&client_id=ABC123');
          });
        }); // that is not trusted by app and sets x-forwarded-proto and x-forwarded-host
        
        describe('that is trusted by strategy and sets x-forwarded-proto', function() {
          var strategy = new OAuth2Strategy({
            authorizationURL: 'https://www.example.com/oauth2/authorize',
            tokenURL: 'https://www.example.com/oauth2/token',
            clientID: 'ABC123',
            clientSecret: 'secret',
            callbackURL: '/auth/example/callback',
            proxy: true
          },
          function(accessToken, refreshToken, profile, done) {});
          
          
          var url;

          before(function(done) {
            chai.passport.use(strategy)
              .redirect(function(u) {
                url = u;
                done();
              })
              .req(function(req) {
                req.url = '/auth/example';
                req.headers.host = 'www.example.net';
                req.headers['x-forwarded-proto'] = 'https';
                req.connection = {};
              })
              .authenticate();
          });

          it('should be redirected', function() {
            expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123');
          });
        }); // that is trusted by strategy and sets x-forwarded-proto
        
        describe('that is trusted by strategy and sets x-forwarded-proto and x-forwarded-host', function() {
          var strategy = new OAuth2Strategy({
            authorizationURL: 'https://www.example.com/oauth2/authorize',
            tokenURL: 'https://www.example.com/oauth2/token',
            clientID: 'ABC123',
            clientSecret: 'secret',
            callbackURL: '/auth/example/callback',
            proxy: true
          },
          function(accessToken, refreshToken, profile, done) {});
          
          
          var url;

          before(function(done) {
            chai.passport.use(strategy)
              .redirect(function(u) {
                url = u;
                done();
              })
              .req(function(req) {
                req.url = '/auth/example';
                req.headers.host = 'server.internal';
                req.headers['x-forwarded-proto'] = 'https';
                req.headers['x-forwarded-host'] = 'www.example.net';
                req.connection = {};
              })
              .authenticate();
          });

          it('should be redirected', function() {
            expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123');
          });
        }); // that is trusted by strategy and sets x-forwarded-proto and x-forwarded-host
        
      }); // from behind a secure proxy
    
    }); // issuing authorization request
    
    
    describe('processing response to authorization request', function() {
      
      describe('that was approved over secure connection', function() {
        var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: '/auth/example/callback',
        },
        function(accessToken, refreshToken, profile, done) {
          if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
          if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
          if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
          if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }

          return done(null, { id: '1234' }, { message: 'Hello' });
        });

        strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
          if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
          if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
          if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }
  
          return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
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
              req.url = '/auth/example';
              req.headers.host = 'www.example.net';
              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.connection = { encrypted: true };
            })
            .authenticate();
        });

        it('should supply user', function() {
          expect(user).to.be.an.object;
          expect(user.id).to.equal('1234');
        });

        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Hello');
        });
      }); // that was approved over secure connection
      
      describe('that was approved over insecure connection', function() {
        var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: '/auth/example/callback',
        },
        function(accessToken, refreshToken, profile, done) {
          if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
          if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
          if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
          if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }

          return done(null, { id: '1234' }, { message: 'Hello' });
        });

        strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
          if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
          if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
          if (options.redirect_uri !== 'http://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }
  
          return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
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
              req.url = '/auth/example';
              req.headers.host = 'www.example.net';
              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.connection = {};
            })
            .authenticate();
        });

        it('should supply user', function() {
          expect(user).to.be.an.object;
          expect(user.id).to.equal('1234');
        });

        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Hello');
        });
      }); // that was approved over insecure connection
      
    }); // processing response to authorization request
    
  }); // using a relative redirect URI
  
});
