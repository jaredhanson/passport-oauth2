var OAuth2Strategy = require('../lib/strategy');


describe('OAuth2Strategy', function() {
    
  var strategy = new OAuth2Strategy({
      authorizationURL: 'https://www.example.com/oauth2/authorize',
      tokenURL: 'https://www.example.com/oauth2/token',
      clientID: 'ABC123',
      clientSecret: 'secret'
    }, function() {});
    
  it('should be named oauth2', function() {
    expect(strategy.name).to.equal('oauth2');
  });
  
  it('should throw if constructed without a verify callback', function() {
    expect(function() {
      new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret'
      });
    }).to.throw(TypeError, 'OAuth2Strategy requires a verify callback');
  });
  
  it('should throw if constructed without a authorizationURL option', function() {
    expect(function() {
      new OAuth2Strategy({
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret'
      }, function() {});
    }).to.throw(TypeError, 'OAuth2Strategy requires a authorizationURL option');
  });
  
  it('should throw if constructed without a tokenURL option', function() {
    expect(function() {
      new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        clientID: 'ABC123',
        clientSecret: 'secret'
      }, function() {});
    }).to.throw(TypeError, 'OAuth2Strategy requires a tokenURL option');
  });
  
  it('should throw if constructed without a clientID option', function() {
    expect(function() {
      new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientSecret: 'secret'
      }, function() {});
    }).to.throw(TypeError, 'OAuth2Strategy requires a clientID option');
  });
  
  it('should throw if constructed without a clientSecret option', function() {
    expect(function() {
      new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123'
      }, function() {});
    }).to.throw(TypeError, 'OAuth2Strategy requires a clientSecret option');
  });
  
  it('should throw if constructed with only a verify callback', function() {
    expect(function() {
      new OAuth2Strategy(function() {});
    }).to.throw(TypeError, 'OAuth2Strategy requires a authorizationURL option');
  });
  
});
