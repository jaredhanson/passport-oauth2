var OAuth2Strategy = require('../lib/strategy');


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
    }); // without a tokenURL option
    
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
    }); // without a tokenURL option
    
    describe('with only a verify callback', function() {
      it('should throw', function() {
        expect(function() {
          new OAuth2Strategy(function() {});
        }).to.throw(TypeError, 'OAuth2Strategy requires a authorizationURL option');
      });
    }); // without a tokenURL option
    
  }); // constructed
  
});
