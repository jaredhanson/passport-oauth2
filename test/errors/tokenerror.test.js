var TokenError = require('../../lib/errors/tokenerror');


describe('TokenError', function() {
    
  describe('constructed without a message', function() {
    var err = new TokenError();
    
    it('should have default properties', function() {
      expect(err.message).to.be.undefined;
      expect(err.code).to.equal('invalid_request');
      expect(err.uri).to.be.undefined;
      expect(err.status).to.equal(500);
    });
    
    it('should format correctly', function() {
      //expect(err.toString()).to.equal('AuthorizationError');
      expect(err.toString().indexOf('TokenError')).to.equal(0);
    });
  });
  
  describe('constructed with a message', function() {
    var err = new TokenError('Mismatched return URI');
    
    it('should have default properties', function() {
      expect(err.message).to.equal('Mismatched return URI');
      expect(err.code).to.equal('invalid_request');
      expect(err.uri).to.be.undefined;
      expect(err.status).to.equal(500);
    });
    
    it('should format correctly', function() {
      expect(err.toString()).to.equal('TokenError: Mismatched return URI');
    });
  });
  
  describe('constructed with a message, code, uri and status', function() {
    var err = new TokenError('Unsupported grant type: foo', 'unsupported_grant_type', 'http://www.example.com/oauth/help', 501);
    
    it('should have default properties', function() {
      expect(err.message).to.equal('Unsupported grant type: foo');
      expect(err.code).to.equal('unsupported_grant_type');
      expect(err.uri).to.equal('http://www.example.com/oauth/help');
      expect(err.status).to.equal(501);
    });
    
    it('should format correctly', function() {
      expect(err.toString()).to.equal('TokenError: Unsupported grant type: foo');
    });
  });
  
});
