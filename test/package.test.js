/* global describe, it, expect */
/* eslint-disable no-unused-expressions, consistent-return */
const strategy = require('..');

describe('passport-oauth2', () => {
  it('should export Strategy constructor as module', () => {
    expect(strategy).to.be.a('function');
    expect(strategy).to.equal(strategy.Strategy);
  });

  it('should export Strategy constructor', () => {
    expect(strategy.Strategy).to.be.a('function');
  });

  it('should export Error constructors', () => {
    expect(strategy.AuthorizationError).to.be.a('function');
    expect(strategy.TokenError).to.be.a('function');
    expect(strategy.InternalOAuthError).to.be.a('function');
  });
});
