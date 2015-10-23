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
    
      it('should save state in session', function() {
        var u = uri.parse(url, true);
        expect(request.session['oauth2:www.example.com'].state).to.have.length(24);
        expect(request.session['oauth2:www.example.com'].state).to.equal(u.query.state);
        expect(request.session['oauth2:www.example.com'].verifier).to.have.length(43);
        expect(request.session['oauth2:www.example.com'].verifier).to.equal('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
      });
    });
  });
  
});
