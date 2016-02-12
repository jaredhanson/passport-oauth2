var OAuth2Strategy = require('../lib/strategy')
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
      it('should throw', function() {
        expect(function() {
          new OAuth2Strategy({
            authorizationURL: 'https://www.example.com/oauth2/authorize',
            tokenURL: 'https://www.example.com/oauth2/token',
            clientID: 'ABC123'
          }, function() {});
        }).to.throw(TypeError, 'OAuth2Strategy requires a clientSecret option');
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
        console.log(options)
        
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
    
  }); // processing response to authorization request
  
});
