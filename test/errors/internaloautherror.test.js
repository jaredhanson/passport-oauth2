/* global describe, it, expect */
/* eslint-disable no-unused-expressions, consistent-return */
const InternalOAuthError = require('../../lib/errors/internaloautherror');


describe('InternalOAuthError', () => {
  describe('constructed without a message', () => {
    const err = new InternalOAuthError();

    it('should format correctly', () => {
      expect(err.toString()).to.equal('InternalOAuthError');
    });
  });

  describe('constructed with a message', () => {
    const err = new InternalOAuthError('oops');

    it('should format correctly', () => {
      expect(err.toString()).to.equal('InternalOAuthError: oops');
    });
  });

  describe('constructed with a message and error', () => {
    const err = new InternalOAuthError('oops', new Error('something is wrong'));

    it('should format correctly', () => {
      expect(err.toString()).to.equal('Error: something is wrong');
    });
  });

  describe('constructed with a message and object with status code and data', () => {
    const err = new InternalOAuthError('oops', { statusCode: 401, data: 'invalid OAuth credentials' });

    it('should format correctly', () => {
      expect(err.toString()).to.equal('InternalOAuthError: oops (status: 401 data: invalid OAuth credentials)');
    });
  });
});
