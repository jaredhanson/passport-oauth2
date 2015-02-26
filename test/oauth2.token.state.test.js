var chai = require('chai')
  , uri = require('url')
  , TokenStateProvider = require('../lib/tokenstateprovider');


describe('TokenStateProvider', function() {

  var tokenStateProvider = new TokenStateProvider({ passphrase: 'correcthorsebatterystaple' });

  describe('should generate states', function() {
    var err
      , state;

    before(function(done) {
      tokenStateProvider.get({}, function(e, s) {
        err = e;
        state = s;
        done();
      });
    });

    it('should not error', function() {
      expect(err).to.not.exist;
    });

    it('should have generated a token', function() {
      expect(state).to.have.length.above(12);
    });
  });

  describe('should verify generated states', function() {
    var err
      , failureCode;

    before(function(done) {
      tokenStateProvider.get({}, function(err, state) {
        if (err) { return done(err); }
        tokenStateProvider.verify({}, state, function(e, f) {
          err = e;
          failureCode = f;
          done();
        })
      });
    });

    it('should not error', function() {
      expect(err).to.not.exist;
    });

    it('should not have a failure code', function() {
      expect(failureCode).to.not.exist;
    });

  });

  describe('should not verify invalid states', function() {
    var errOrFailure
      , failureCode;

    before(function(done) {
      tokenStateProvider.verify({}, '8980c099ec7024de7f710694f04fbd58', function(e, f) {
        errOrFailure = e;
        failureCode = f;
        done();
      });
    });

    it('should an error', function() {
      expect(errOrFailure).to.be.an.object;
      expect(errOrFailure.message).to.equal('Invalid authorization request state.');
    });

    it('should not have a failure code', function() {
      expect(failureCode).to.equal(403);
    });

  });

  describe('should not verify old tokens', function() {
    var errOrFailure
      , failureCode;

    before(function(done) {
      tokenStateProvider.verify({}, '0d07694f432e5b2e002f25a4cd6906a3c238605c1e7a089ba3f750b29b60a022', function(e, f) {
        errOrFailure = e;
        failureCode = f;
        done();
      });
    });

    it('should an error', function() {
      expect(errOrFailure).to.be.an.object;
      expect(errOrFailure.message).to.equal('Invalid authorization request state.');
    });

    it('should not have a failure code', function() {
      expect(failureCode).to.equal(403);
    });

  });

  describe('should not verify old tokens', function() {
    var errOrFailure
      , failureCode;

    before(function(done) {
      tokenStateProvider.verify({}, '', function(e, f) {
        errOrFailure = e;
        failureCode = f;
        done();
      });
    });

    it('should an error', function() {
      expect(errOrFailure).to.be.an.object;
      expect(errOrFailure.message).to.equal('Invalid authorization request state.');
    });

    it('should not have a failure code', function() {
      expect(failureCode).to.equal(403);
    });

  });


});
