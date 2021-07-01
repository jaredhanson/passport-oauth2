var chai = require('chai')
  , uri = require('url')
  , OAuth2Strategy = require('../lib/strategy');


describe('OAuth2Strategy', function() {
    
  describe('without state:true option', function() {
    it('should throw', function() {
      expect(function() {
        new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          pkce: true
        }, function() {});
      }).to.throw(TypeError, 'OAuth2Strategy requires `state: true` option when PKCE is enabled');
    });
  }); // without a verify callback
    
  describe('with PKCE true transformation method', function() {
    var mockCrypto = {
      pseudoRandomBytes: function(len) {
        if (len !== 32) { throw new Error('xyz'); }
        // https://tools.ietf.org/html/rfc7636#appendix-B
        return new Buffer(
          [116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
          187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
          132, 141, 121]
        );
      }
    }
    
    var OAuth2Strategy = require('proxyquire')('../lib/strategy', { crypto: mockCrypto });
    var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        state: true,
        pkce: true
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
          return done(null, { id: '1234' }, { message: 'Hello' });
        }
        return done(null, false);
      });

    strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
      if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
      if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
      if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }
      if (options.code_verifier !== 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk') { return callback(new Error('incorrect options.verifier loaded from session')); }

      return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
    }

    describe('handling a request to be redirected for authorization', function() {
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
        expect(u.query.code_challenge).to.have.length(43);
        expect(u.query.code_challenge).to.equal('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
        expect(u.query.code_challenge_method).to.equal('S256');
      });
    
      it('should save verifier in session', function() {
        var u = uri.parse(url, true);
        expect(request.session['oauth2:www.example.com'].state.handle).to.have.length(24);
        expect(request.session['oauth2:www.example.com'].state.handle).to.equal(u.query.state);
        expect(request.session['oauth2:www.example.com'].state.code_verifier).to.have.length(43);
        expect(request.session['oauth2:www.example.com'].state.code_verifier).to.equal('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
        expect(request.session['oauth2:www.example.com'].state.state).to.be.undefined;
      });
    });
    
    describe('handling a request to be redirected for authorization with state', function() {
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
          .authenticate({ state: { returnTo: '/somewhere' }});
      });

      it('should be redirected', function() {
        var u = uri.parse(url, true);
        expect(u.query.state).to.have.length(24);
        expect(u.query.code_challenge).to.have.length(43);
        expect(u.query.code_challenge).to.equal('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
        expect(u.query.code_challenge_method).to.equal('S256');
      });
    
      it('should save verifier in session', function() {
        var u = uri.parse(url, true);
        expect(request.session['oauth2:www.example.com'].state.handle).to.have.length(24);
        expect(request.session['oauth2:www.example.com'].state.handle).to.equal(u.query.state);
        expect(request.session['oauth2:www.example.com'].state.code_verifier).to.have.length(43);
        expect(request.session['oauth2:www.example.com'].state.code_verifier).to.equal('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
        expect(request.session['oauth2:www.example.com'].state.state).to.deep.equal({ returnTo: '/somewhere' });
      });
    });
    
    describe('handling a request to be redirected for authorization with state set to boolean true', function() {
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
          .authenticate({ state: true });
      });

      it('should be redirected', function() {
        var u = uri.parse(url, true);
        expect(u.query.state).to.have.length(24);
        expect(u.query.code_challenge).to.have.length(43);
        expect(u.query.code_challenge).to.equal('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
        expect(u.query.code_challenge_method).to.equal('S256');
      });
    
      it('should save verifier in session', function() {
        var u = uri.parse(url, true);
        expect(request.session['oauth2:www.example.com'].state.handle).to.have.length(24);
        expect(request.session['oauth2:www.example.com'].state.handle).to.equal(u.query.state);
        expect(request.session['oauth2:www.example.com'].state.code_verifier).to.have.length(43);
        expect(request.session['oauth2:www.example.com'].state.code_verifier).to.equal('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
        expect(request.session['oauth2:www.example.com'].state.state).to.equal(true);
      });
    });
    
    describe('handling a request to be redirected for authorization with state set to boolean false', function() {
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
          .authenticate({ state: false });
      });

      it('should be redirected', function() {
        var u = uri.parse(url, true);
        expect(u.query.state).to.have.length(24);
        expect(u.query.code_challenge).to.have.length(43);
        expect(u.query.code_challenge).to.equal('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
        expect(u.query.code_challenge_method).to.equal('S256');
      });
    
      it('should save verifier in session', function() {
        var u = uri.parse(url, true);
        expect(request.session['oauth2:www.example.com'].state.handle).to.have.length(24);
        expect(request.session['oauth2:www.example.com'].state.handle).to.equal(u.query.state);
        expect(request.session['oauth2:www.example.com'].state.code_verifier).to.have.length(43);
        expect(request.session['oauth2:www.example.com'].state.code_verifier).to.equal('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
        expect(request.session['oauth2:www.example.com'].state.state).to.be.undefined;
      });
    });
    
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
        expect(request.session['oauth2:www.example.com'].state.handle).to.have.length(24);
        expect(request.session['oauth2:www.example.com'].state.handle).to.equal(u.query.state);
        expect(request.session['oauth2:www.example.com'].state.code_verifier).to.have.length(43);
        expect(request.session['oauth2:www.example.com'].state.code_verifier).to.equal('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
      });
      
      it('should preserve other data in session', function() {
        expect(request.session['oauth2:www.example.com'].foo).to.equal('bar');
      });
    }); // that redirects to service provider with other data in session

    describe('processing response to authorization request', function() {
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
            req.session['oauth2:www.example.com']['state'] = { handle: 'DkbychwKu8kBaJoLE5yeR5NK', code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' };
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
        expect(info.state).to.be.undefined;
      });

      it('should remove state with verifier from session', function() {
        expect(request.session['oauth2:www.example.com']).to.be.undefined;
      });
    });
    
    describe('processing response to authorization request with state', function() {
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
            req.session['oauth2:www.example.com']['state'] = { handle: 'DkbychwKu8kBaJoLE5yeR5NK', code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk', state: { returnTo: '/somewhere' } };
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
        expect(info.state).to.deep.equal({ returnTo: '/somewhere' });
      });

      it('should remove state with verifier from session', function() {
        expect(request.session['oauth2:www.example.com']).to.be.undefined;
      });
    });
    
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
            req.session['oauth2:www.example.com']['state'] = { handle: 'DkbychwKu8kBaJoLE5yeR5NK', code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' };
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
  });
    
  describe('with PKCE plain transformation method', function() {
    var mockCrypto = {
      pseudoRandomBytes: function(len) {
        if (len !== 32) { throw new Error('xyz'); }
        return new Buffer(
          [116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
          187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
          132, 141, 121]
        );
      }
    }
    
    var OAuth2Strategy = require('proxyquire')('../lib/strategy', { crypto: mockCrypto });
    var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        state: true,
        pkce: 'plain'
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
          return done(null, { id: '1234' }, { message: 'Hello' });
        }
        return done(null, false);
      });

    strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
      if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
      if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
      if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }
      if (options.code_verifier !== 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk') { return callback(new Error('incorrect options.verifier loaded from session')); }

      return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
    }

    describe('handling a request to be redirected for authorization', function() {
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
        expect(u.query.code_challenge).to.have.length(43);
        expect(u.query.code_challenge).to.equal('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')
        expect(u.query.code_challenge_method).to.equal('plain');
      });
    
      it('should save verifier in session', function() {
        var u = uri.parse(url, true);
        expect(request.session['oauth2:www.example.com'].state.handle).to.have.length(24);
        expect(request.session['oauth2:www.example.com'].state.handle).to.equal(u.query.state);
        expect(request.session['oauth2:www.example.com'].state.code_verifier).to.have.length(43);
        expect(request.session['oauth2:www.example.com'].state.code_verifier).to.equal('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
      });
    });

    describe('processing response to authorization request', function() {
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
            req.session['oauth2:www.example.com']['state'] = { handle: 'DkbychwKu8kBaJoLE5yeR5NK', code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' };
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

      it('should remove state with verifier from session', function() {
        expect(request.session['oauth2:www.example.com']).to.be.undefined;
      });
    });
  });
  
  describe('with PKCE S256 transformation method', function() {
    var mockCrypto = {
      pseudoRandomBytes: function(len) {
        if (len !== 32) { throw new Error('xyz'); }
        // https://tools.ietf.org/html/rfc7636#appendix-B
        return new Buffer(
          [116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
          187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
          132, 141, 121]
        );
      }
    }
    
    var OAuth2Strategy = require('proxyquire')('../lib/strategy', { crypto: mockCrypto });
    var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        state: true,
        pkce: 'S256'
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
          return done(null, { id: '1234' }, { message: 'Hello' });
        }
        return done(null, false);
      });

    strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
      if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
      if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
      if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }
      if (options.code_verifier !== 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk') { return callback(new Error('incorrect options.verifier loaded from session')); }

      return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
    }

    describe('handling a request to be redirected for authorization', function() {
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
        expect(u.query.code_challenge).to.have.length(43);
        expect(u.query.code_challenge).to.equal('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
        expect(u.query.code_challenge_method).to.equal('S256');
      });
    
      it('should save verifier in session', function() {
        var u = uri.parse(url, true);
        expect(request.session['oauth2:www.example.com'].state.handle).to.have.length(24);
        expect(request.session['oauth2:www.example.com'].state.handle).to.equal(u.query.state);
        expect(request.session['oauth2:www.example.com'].state.code_verifier).to.have.length(43);
        expect(request.session['oauth2:www.example.com'].state.code_verifier).to.equal('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
      });
    });

    describe('processing response to authorization request', function() {
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
            req.session['oauth2:www.example.com']['state'] = { handle: 'DkbychwKu8kBaJoLE5yeR5NK', code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' };
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

      it('should remove state with verifier from session', function() {
        expect(request.session['oauth2:www.example.com']).to.be.undefined;
      });
    });
  });

  describe('with exceptions', function() {
    var mockCrypto = {
      pseudoRandomBytes: function(len) {
        if (len !== 32) { throw new Error('xyz'); }
        // https://tools.ietf.org/html/rfc7636#appendix-B
        return new Buffer(
          [116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
          187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
          132, 141, 121]
        );
      }
    }

    describe('with unknown encoding method', function() {

      var OAuth2Strategy = require('proxyquire')('../lib/strategy', { crypto: mockCrypto });
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        state: true,
        pkce: 'unknown'
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
          return done(null, { id: '1234' }, { message: 'Hello' });
        }
        return done(null, false);
      });

      var err;

      before(function(done) {
        chai.passport.use(strategy)
          .error(function(e) {
            err = e;
            done();
          })
          .req(function(req) {
            request = req;
            req.session = {};
          })
          .authenticate();
      });

      it('should error', function() {
        expect(err.message).to.equal('Unsupported code verifier transformation method: unknown');
      });
    });

    describe('with unknown verifier', function() {

      var OAuth2Strategy = require('proxyquire')('../lib/strategy', { crypto: mockCrypto });
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        state: true,
        pkce: 'S256'
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
          return done(null, { id: '1234' }, { message: 'Hello' });
        }
        return done(null, false);
      });

      var err;

      before(function(done) {
        chai.passport.use(strategy)
          .fail(function(i) {
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
            req.session['oauth2:www.example.com']['state'] = { handle: 'DkbychwKu8kBaJoLE5yeR5NK'};
          })
          .authenticate();
      });

      it('should not supply info', function() {
        expect(info).to.be.undefined;
      });
    });
    
    describe('that fails due to state being invalid', function() {
      var OAuth2Strategy = require('proxyquire')('../lib/strategy', { crypto: mockCrypto });
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        state: true,
        pkce: 'S256'
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
          return done(null, { id: '1234' }, { message: 'Hello' });
        }
        return done(null, false);
      });
      
      
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
            req.session['oauth2:www.example.com']['state'] = { handle: 'DkbychwKu8kBaJoLE5yeR5NK', code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' };
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
      var OAuth2Strategy = require('proxyquire')('../lib/strategy', { crypto: mockCrypto });
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        state: true,
        pkce: 'S256'
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
          return done(null, { id: '1234' }, { message: 'Hello' });
        }
        return done(null, false);
      });
      
      
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
      var OAuth2Strategy = require('proxyquire')('../lib/strategy', { crypto: mockCrypto });
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        state: true,
        pkce: 'S256'
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
          return done(null, { id: '1234' }, { message: 'Hello' });
        }
        return done(null, false);
      });
      
      
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
      var OAuth2Strategy = require('proxyquire')('../lib/strategy', { crypto: mockCrypto });
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        state: true,
        pkce: 'S256'
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
          return done(null, { id: '1234' }, { message: 'Hello' });
        }
        return done(null, false);
      });
      
      
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
    
  });
});
