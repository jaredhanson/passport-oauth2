var OAuth2Strategy = require('../lib/strategy')
  , AuthorizationError = require('../lib/errors/authorizationerror')
  , TokenError = require('../lib/errors/tokenerror')
  , InternalOAuthError = require('../lib/errors/internaloautherror')
  , chai = require('chai');


describe('form_post', function() {
  
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
          req.body = {};
          req.body.code = 'SplxlOBeZQQYbYS6WxSbIA';
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
  
  describe('processing response to authorization request', function() {
    var strategy = new OAuth2Strategy({
      authorizationURL: 'https://www.example.com/oauth2/authorize',
      tokenURL: 'https://www.example.com/oauth2/token',
      clientID: 'ABC123',
      clientSecret: 'secret',
      callbackURL: 'https://www.example.net/auth/example/callback',
      store: true
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
          
            req.body = {};
            req.body.code = 'SplxlOBeZQQYbYS6WxSbIA';
            req.body.state = 'DkbychwKu8kBaJoLE5yeR5NK';
            req.session = {};
            req.session['oauth2:www.example.com'] = {};
            req.session['oauth2:www.example.com']['state'] = { handle: 'DkbychwKu8kBaJoLE5yeR5NK' };
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
    
      it('should remove state from session', function() {
        expect(request.session['oauth2:www.example.com']).to.be.undefined;
      });
    }); // that was approved
    
  });
  
});
