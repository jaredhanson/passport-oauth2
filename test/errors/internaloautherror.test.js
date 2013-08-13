var InternalOAuthError = require('../../lib/errors/internaloautherror');


describe('InternalOAuthError', function() {
    
  describe('constructed without a message', function() {
    var err = new InternalOAuthError();
    
    it('should format correctly', function() {
      expect(err.toString()).to.equal('InternalOAuthError');
    });
  });
    
  describe('constructed with a message', function() {
    var err = new InternalOAuthError('oops');
    
    it('should format correctly', function() {
      expect(err.toString()).to.equal('InternalOAuthError: oops');
    });
  });
  
  describe('constructed with a message and error', function() {
    var err = new InternalOAuthError('oops', new Error('something is wrong'));
    
    it('should format correctly', function() {
      expect(err.toString()).to.equal('Error: something is wrong');
    });
  });
  
  describe('constructed with a message and object with status code and data', function() {
    var err = new InternalOAuthError('oops', { statusCode: 401, data: 'invalid OAuth credentials' });
    
    it('should format correctly', function() {
      expect(err.toString()).to.equal('InternalOAuthError: oops (status: 401 data: invalid OAuth credentials)');
    });
  });
  
});
