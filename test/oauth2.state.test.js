var chai = require('chai')
  , uri = require('url')
  , OAuth2Strategy = require('../lib/strategy');


describe('OAuth2Strategy', function() {
    
  describe('with state checking enabled', function() {
    var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        state: true
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
          return done(null, { id: '1234' }, { message: 'Hello' });
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
    
    describe('handling an authorized return request with correct state', function() {
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
    });
    
    describe('handling an authorized return request with incorrect state', function() {
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
    });
    
    describe('handling an authorized return request with session that lacks key', function() {
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
    });
    
    describe('handling an authorized return request with session that has key but no state', function() {
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
    });
    
    describe('handling an authorized return request without session', function() {
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
        expect(err.message).to.equal('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?');
      });
    });
  
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
      });
      
      it('should save state in session', function() {
        var u = uri.parse(url, true);
        
        expect(request.session['oauth2:www.example.com'].state).to.have.length(24);
        expect(request.session['oauth2:www.example.com'].state).to.equal(u.query.state);
      });
    });
    
    describe('handling a request without session to be redirected for authorization', function() {
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
        expect(err.message).to.equal('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?');
      });
    });
  });
  
  describe('with state checking enabled and session key option', function() {
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
        if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
          return done(null, { id: '1234' }, { message: 'Hello' });
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
    
    describe('handling an authorized return request with correct state', function() {
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
    });
  
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
      });
      
      it('should save state in session', function() {
        var u = uri.parse(url, true);
        
        expect(request.session['oauth2:example'].state).to.have.length(24);
        expect(request.session['oauth2:example'].state).to.equal(u.query.state);
      });
    });
  });
    
  describe('with explicit state declared as authenticate option', function() {
    var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback'
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
          return done(null, { id: '1234' }, { message: 'Hello' });
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
  
    describe('handling a request to be redirected for authorization', function() {
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
    });
    
  });
  
});
