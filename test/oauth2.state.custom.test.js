var OAuth2Strategy = require('../lib/strategy')
  , AuthorizationError = require('../lib/errors/authorizationerror')
  , TokenError = require('../lib/errors/tokenerror')
  , InternalOAuthError = require('../lib/errors/internaloautherror')
  , chai = require('chai')
  , uri = require('url');


describe('OAuth2Strategy', function() {
  
  describe('with custom state store that accepts meta argument', function() {
    function CustomStore() {
    }

    CustomStore.prototype.store = function(req, cb) {
      if (req.url !== '/me') { return cb(new Error('incorrect req argument')); }
      
      req.customStoreStoreCalled = req.customStoreStoreCalled ? req.customStoreStoreCalled++ : 1;
      return cb(null, 'foos7473');
    };
    
    CustomStore.prototype.verify = function(req, state, meta, cb) {
    };
    
    
    describe('issuing authorization request', function() {
      var strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        store: new CustomStore()
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
              req.url = '/me';
            })
            .authenticate();
        });
  
        it('should be redirected', function() {
          expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&state=foos7473&client_id=ABC123');
        });
      
        it('should store request token in custom store', function() {
          expect(request.customStoreStoreCalled).to.equal(1);
        });
      }); // that redirects to service provider
      
    }); // issuing authorization request
    
  }); // with custom state store that accepts meta argument
  
});
