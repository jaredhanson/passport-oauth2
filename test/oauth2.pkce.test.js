var chai = require('chai')
  , uri = require('url')
  , OAuth2Strategy = require('../lib/strategy');


describe('OAuth2Strategy', function() {
    
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
        pkceMethod: 'plain'
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
        expect(request.session['oauth2:www.example.com'].state.verifier).to.have.length(43);
        expect(request.session['oauth2:www.example.com'].state.verifier).to.equal('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
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
            req.session['oauth2:www.example.com']['state'] = { handle: 'DkbychwKu8kBaJoLE5yeR5NK', verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' };
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
        pkceMethod: 'S256'
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
        expect(request.session['oauth2:www.example.com'].state.verifier).to.have.length(43);
        expect(request.session['oauth2:www.example.com'].state.verifier).to.equal('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
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
            req.session['oauth2:www.example.com']['state'] = { handle: 'DkbychwKu8kBaJoLE5yeR5NK', verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' };
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
        pkceMethod: 'unknown'
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
        pkceMethod: 'S256'
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
          .fail(function(e, code) {
            err = e;
            err.statusCode = code;
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

      it('should error', function() {
        expect(err.statusCode).to.equal(403);
        expect(err.message).to.equal('Unable to load stored code verifier.');
      });
    });
  });
});
