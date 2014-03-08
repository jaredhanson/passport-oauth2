var chai = require('chai')
  , OAuth2Strategy = require('../lib/strategy');


describe('OAuth2Strategy', function() {
    
  describe('with scope option', function() {
    var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        scope: 'email'
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
      
      if (code == 'SplxlOBeZQQYbYS6WxSbIA') {
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
          .authenticate();
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&scope=email&client_id=ABC123');
      });
    });
  });
  
  describe('with scope separator option', function() {
    var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        scopeSeparator: ','
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
      
      if (code == 'SplxlOBeZQQYbYS6WxSbIA') {
        callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
      } else {
        callback(null, 'wrong-access-token', 'wrong-refresh-token');
      }
    }
  
    describe('handling a request to be redirected for authorization with multiple scopes', function() {
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
    });
  });
  
  describe('with relative callback URL option', function() {
    var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: '/auth/example/callback',
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
          return done(null, { id: '1234' }, { message: 'Hello' });
        } else if (accessToken == '2YotnFZFEjr1zCsicMWpAA+INSECURE' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA+INSECURE') { 
          return done(null, { id: '1234' }, { message: 'Hello (INSECURE)' });
        }
        return done(null, false);
      });
  
    // inject a "mock" oauth2 instance
    strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
      if (options.grant_type !== 'authorization_code') { return callback(null, 'wrong-access-token', 'wrong-refresh-token'); }
      
      if (code == 'SplxlOBeZQQYbYS6WxSbIA' && options.redirect_uri == 'https://www.example.net/auth/example/callback') {
        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example', expires_in: 3600, example_parameter: 'example_value' });
      } else if (code == 'SplxlOBeZQQYbYS6WxSbIA+INSECURE' && options.redirect_uri == 'http://www.example.net/auth/example/callback') {
        return callback(null, '2YotnFZFEjr1zCsicMWpAA+INSECURE', 'tGzv3JOkF0XG5Qx2TlKWIA+INSECURE', { token_type: 'example', expires_in: 3600, example_parameter: 'example_value' });
      } else {
        return callback(null, 'wrong-access-token', 'wrong-refresh-token');
      }
    }
  
    describe('handling an authorized return request on secure connection', function() {
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
    });
  
    describe('handling an authorized return request on insecure connection', function() {
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
            req.query.code = 'SplxlOBeZQQYbYS6WxSbIA+INSECURE';
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
        expect(info.message).to.equal('Hello (INSECURE)');
      });
    });
  
    describe('handling a request on secure connection to be redirected for authorization', function() {
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
    });
  
    describe('handling a request on insecure connection to be redirected for authorization', function() {
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
    });
  
    describe('handling a request to be redirected for authorization from behind a secure proxy that is trusted by app', function() {
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
    });
  
    describe('handling a request to be redirected for authorization from behind a secure proxy that sets x-forwarded-host that is trusted by app', function() {
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
    });
    
    describe('handling a request to be redirected for authorization that contains untrusted x-forwarded-proto header', function() {
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
    });

    describe('handling a request to be redirected for authorization that contains untrusted x-forwarded-host header', function() {
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
    });
  });
  
  describe('with relative callback URL and trust proxy option', function() {
    var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: '/auth/example/callback',
        proxy: true
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
          return done(null, { id: '1234' }, { message: 'Hello' });
        } else if (accessToken == '2YotnFZFEjr1zCsicMWpAA+INSECURE' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA+INSECURE') { 
          return done(null, { id: '1234' }, { message: 'Hello (INSECURE)' });
        }
        return done(null, false);
      });
  
    // inject a "mock" oauth2 instance
    strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
      if (options.grant_type !== 'authorization_code') { return callback(null, 'wrong-access-token', 'wrong-refresh-token'); }
      
      if (code == 'SplxlOBeZQQYbYS6WxSbIA' && options.redirect_uri == 'https://www.example.net/auth/example/callback') {
        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example', expires_in: 3600, example_parameter: 'example_value' });
      } else if (code == 'SplxlOBeZQQYbYS6WxSbIA+INSECURE' && options.redirect_uri == 'http://www.example.net/auth/example/callback') {
        return callback(null, '2YotnFZFEjr1zCsicMWpAA+INSECURE', 'tGzv3JOkF0XG5Qx2TlKWIA+INSECURE', { token_type: 'example', expires_in: 3600, example_parameter: 'example_value' });
      } else {
        return callback(null, 'wrong-access-token', 'wrong-refresh-token');
      }
    }
    
    describe('handling a request to be redirected for authorization that contains trusted x-forwarded-proto header', function() {
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
    });

    describe('handling a request to be redirected for authorization that contains trusted x-forwarded-host header', function() {
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
    });
  });
  
});

