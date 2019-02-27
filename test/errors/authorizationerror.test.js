/* global describe, it, expect */
/* eslint-disable no-unused-expressions, consistent-return */
const AuthorizationError = require('../../lib/errors/authorizationerror');


describe('AuthorizationError', () => {
  describe('constructed without a message', () => {
    const err = new AuthorizationError();

    it('should have default properties', () => {
      expect(err.message).to.equal('');
      expect(err.code).to.equal('server_error');
      expect(err.uri).to.be.undefined;
      expect(err.status).to.equal(500);
    });

    it('should format correctly', () => {
      // expect(err.toString()).to.equal('AuthorizationError');
      expect(err.toString().indexOf('AuthorizationError')).to.equal(0);
    });
  });

  describe('constructed with a message', () => {
    const err = new AuthorizationError('Invalid return URI');

    it('should have default properties', () => {
      expect(err.message).to.equal('Invalid return URI');
      expect(err.code).to.equal('server_error');
      expect(err.uri).to.be.undefined;
      expect(err.status).to.equal(500);
    });

    it('should format correctly', () => {
      expect(err.toString()).to.equal('AuthorizationError: Invalid return URI');
    });
  });

  describe('constructed with a message and access_denied code', () => {
    const err = new AuthorizationError('Access denied', 'access_denied');

    it('should have default properties', () => {
      expect(err.message).to.equal('Access denied');
      expect(err.code).to.equal('access_denied');
      expect(err.uri).to.be.undefined;
      expect(err.status).to.equal(403);
    });
  });

  describe('constructed with a message and server_error code', () => {
    const err = new AuthorizationError('Server error', 'server_error');

    it('should have default properties', () => {
      expect(err.message).to.equal('Server error');
      expect(err.code).to.equal('server_error');
      expect(err.uri).to.be.undefined;
      expect(err.status).to.equal(502);
    });
  });

  describe('constructed with a message and temporarily_unavailable code', () => {
    const err = new AuthorizationError('Temporarily unavailable', 'temporarily_unavailable');

    it('should have default properties', () => {
      expect(err.message).to.equal('Temporarily unavailable');
      expect(err.code).to.equal('temporarily_unavailable');
      expect(err.uri).to.be.undefined;
      expect(err.status).to.equal(503);
    });
  });

  describe('constructed with a message, code, uri and status', () => {
    const err = new AuthorizationError('Unsupported response type: foo', 'unsupported_response_type', 'http://www.example.com/oauth/help', 501);

    it('should have default properties', () => {
      expect(err.message).to.equal('Unsupported response type: foo');
      expect(err.code).to.equal('unsupported_response_type');
      expect(err.uri).to.equal('http://www.example.com/oauth/help');
      expect(err.status).to.equal(501);
    });

    it('should format correctly', () => {
      expect(err.toString()).to.equal('AuthorizationError: Unsupported response type: foo');
    });
  });
});
