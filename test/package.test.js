var strategy = require('..');

describe('passport-oauth2', function() {
  
  it('should export Strategy constructor as module', function() {
    expect(strategy).to.be.a('function');
    expect(strategy).to.equal(strategy.Strategy);
  });
  
  it('should export Strategy constructor', function() {
    expect(strategy.Strategy).to.be.a('function');
  });
  
  it('should export Error constructors', function() {
    expect(strategy.AuthorizationError).to.be.a('function');
    expect(strategy.TokenError).to.be.a('function');
    expect(strategy.InternalOAuthError).to.be.a('function');
  });
  
});
