var OAuth2Strategy = require('../lib/strategy')
  , AuthorizationError = require('../lib/errors/authorizationerror')
  , TokenError = require('../lib/errors/tokenerror')
  , InternalOAuthError = require('../lib/errors/internaloautherror')
  , chai = require('chai')
  , uri = require('url');


describe('OAuth2Strategy', function() {
  
  describe('using default session state store', function() {
    
    describe('issuing authorization request', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        state: true
      },
      function(accessToken, refreshToken, profile, done) {});
      
      
      describe('that redirects to service provider', function() {
        var request, url;
  
        before(function(done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              url = u;
              done();
            })
            .req(function(req) {
              request = req;
              req.session = {};
            })
            .authenticate();
        });
  
        it('should be redirected', function() {
          var u = uri.parse(url, true);
          expect(u.query.state).to.have.length(24);
        });
      
        it('should save state in session', function() {
          var u = uri.parse(url, true);
        
          expect(request.session['oauth2:www.example.com'].state).to.have.length(24);
          expect(request.session['oauth2:www.example.com'].state).to.equal(u.query.state);
        });
      }); // that redirects to service provider
      
      describe('that redirects to service provider with other data in session', function() {
        var request, url;
  
        before(function(done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              url = u;
              done();
            })
            .req(function(req) {
              request = req;
              req.session = {};
              req.session['oauth2:www.example.com'] = {};
              req.session['oauth2:www.example.com'].foo = 'bar';
            })
            .authenticate();
        });
  
        it('should be redirected', function() {
          var u = uri.parse(url, true);
          expect(u.query.state).to.have.length(24);
        });
      
        it('should save state in session', function() {
          var u = uri.parse(url, true);
        
          expect(request.session['oauth2:www.example.com'].state).to.have.length(24);
          expect(request.session['oauth2:www.example.com'].state).to.equal(u.query.state);
        });
        
        it('should preserve other data in session', function() {
          expect(request.session['oauth2:www.example.com'].foo).to.equal('bar');
        });
      }); // that redirects to service provider with other data in session
      
      describe('that errors due to lack of session support in app', function() {
        var request, err;
  
        before(function(done) {
          chai.passport.use(strategy)
            .error(function(e) {
              err = e;
              done();
            })
            .req(function(req) {
              request = req;
            })
            .authenticate();
        });
  
        it('should error', function() {
          expect(err).to.be.an.instanceof(Error)
          expect(err.message).to.equal('OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?');
        });
      }); // that errors due to lack of session support in app
      
    }); // issuing authorization request
    
    describe('issuing authorization request to authorization server using authorization endpoint that has query parameters including state', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize?foo=bar&state=baz',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        state: true
      },
      function(accessToken, refreshToken, profile, done) {});
      
      
      describe('that redirects to service provider', function() {
        var request, url;
  
        before(function(done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              url = u;
              done();
            })
            .req(function(req) {
              request = req;
              req.session = {};
            })
            .authenticate();
        });
  
        it('should be redirected', function() {
          var u = uri.parse(url, true);
          expect(u.query.foo).equal('bar');
          expect(u.query.state).to.have.length(24);
        });
      
        it('should save state in session', function() {
          var u = uri.parse(url, true);
        
          expect(request.session['oauth2:www.example.com'].state).to.have.length(24);
          expect(request.session['oauth2:www.example.com'].state).to.equal(u.query.state);
        });
      }); // that redirects to service provider
      
    }); // issuing authorization request to authorization server using authorization endpoint that has query parameters including state
    
    describe('processing response to authorization request', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        state: true
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
      
      
      describe('that was approved', function() {
        var request
          , user
          , info;
  
        before(function(done) {
          chai.passport.use(strategy)
            .success(function(u, i) {
              user = u;
              info = i;
              done();
            })
            .req(function(req) {
              request = req;
            
              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.session = {};
              req.session['oauth2:www.example.com'] = {};
              req.session['oauth2:www.example.com']['state'] = 'DkbychwKu8kBaJoLE5yeR5NK';
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
      
        it('should remove state from session', function() {
          expect(request.session['oauth2:www.example.com']).to.be.undefined;
        });
      }); // that was approved
      
      describe('that was approved with other data in the session', function() {
        var request
          , user
          , info;
  
        before(function(done) {
          chai.passport.use(strategy)
            .success(function(u, i) {
              user = u;
              info = i;
              done();
            })
            .req(function(req) {
              request = req;
            
              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.session = {};
              req.session['oauth2:www.example.com'] = {};
              req.session['oauth2:www.example.com']['state'] = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.session['oauth2:www.example.com'].foo = 'bar';
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
      
        it('should preserve other data from session', function() {
          expect(request.session['oauth2:www.example.com'].state).to.be.undefined;
          expect(request.session['oauth2:www.example.com'].foo).to.equal('bar');
        });
      }); // that was approved with other data in the session
      
      describe('that fails due to state being invalid', function() {
        var request
          , info, status;
  
        before(function(done) {
          chai.passport.use(strategy)
            .fail(function(i, s) {
              info = i;
              status = s;
              done();
            })
            .req(function(req) {
              request = req;
            
              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK-WRONG';
              req.session = {};
              req.session['oauth2:www.example.com'] = {};
              req.session['oauth2:www.example.com']['state'] = 'DkbychwKu8kBaJoLE5yeR5NK';
            })
            .authenticate();
        });
  
        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Invalid authorization request state.');
        });
      
        it('should supply status', function() {
          expect(status).to.equal(403);
        });
      
        it('should remove state from session', function() {
          expect(request.session['oauth2:www.example.com']).to.be.undefined;
        });
      }); // that fails due to state being invalid
      
      describe('that fails due to provider-specific state not found in session', function() {
        var request
          , info, status;
  
        before(function(done) {
          chai.passport.use(strategy)
            .fail(function(i, s) {
              info = i;
              status = s;
              done();
            })
            .req(function(req) {
              request = req;
            
              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.session = {};
            })
            .authenticate();
        });
  
        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Unable to verify authorization request state.');
        });
      
        it('should supply status', function() {
          expect(status).to.equal(403);
        });
      }); // that fails due to state not found in session
      
      describe('that fails due to provider-specific state lacking state value', function() {
        var request
          , info, status;
  
        before(function(done) {
          chai.passport.use(strategy)
            .fail(function(i, s) {
              info = i;
              status = s;
              done();
            })
            .req(function(req) {
              request = req;
            
              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.session = {};
              req.session['oauth2:www.example.com'] = {};
            })
            .authenticate();
        });
  
        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Unable to verify authorization request state.');
        });
      
        it('should supply status', function() {
          expect(status).to.equal(403);
        });
      }); // that fails due to provider-specific state lacking state value
      
      describe('that errors due to lack of session support in app', function() {
        var request
          , err;
  
        before(function(done) {
          chai.passport.use(strategy)
            .error(function(e) {
              err = e;
              done();
            })
            .req(function(req) {
              request = req;
            
              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
            })
            .authenticate();
        });
  
        it('should error', function() {
          expect(err).to.be.an.instanceof(Error)
          expect(err.message).to.equal('OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?');
        });
      }); // that errors due to lack of session support in app
      
    }); // processing response to authorization request
    
  }); // using default session state store
  
  
  describe('using default session state store with session key option', function() {
    var strategy = new OAuth2Strategy({
      authorizationURL: 'https://www.example.com/oauth2/authorize',
      tokenURL: 'https://www.example.com/oauth2/token',
      clientID: 'ABC123',
      clientSecret: 'secret',
      callbackURL: 'https://www.example.net/auth/example/callback',
      state: true,
      sessionKey: 'oauth2:example'
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
    
    
    describe('issuing authorization request', function() {
      
      describe('that redirects to service provider', function() {
        var request, url;
  
        before(function(done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              url = u;
              done();
            })
            .req(function(req) {
              request = req;
              req.session = {};
            })
            .authenticate();
        });
  
        it('should be redirected', function() {
          var u = uri.parse(url, true);
          expect(u.query.state).to.have.length(24);
        });
      
        it('should save state in session', function() {
          var u = uri.parse(url, true);
        
          expect(request.session['oauth2:example'].state).to.have.length(24);
          expect(request.session['oauth2:example'].state).to.equal(u.query.state);
        });
      }); // that redirects to service provider
      
    }); // issuing authorization request
    
    describe('processing response to authorization request', function() {
      
      describe('that was approved', function() {
        var request
          , user
          , info;
  
        before(function(done) {
          chai.passport.use(strategy)
            .success(function(u, i) {
              user = u;
              info = i;
              done();
            })
            .req(function(req) {
              request = req;
            
              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.session = {};
              req.session['oauth2:example'] = {};
              req.session['oauth2:example']['state'] = 'DkbychwKu8kBaJoLE5yeR5NK';
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
      
        it('should remove state from session', function() {
          expect(request.session['oauth2:example']).to.be.undefined;
        });
      }); // that was approved
      
    }); // processing response to authorization request
    
  }); // using default session state store with session key option
  
});
