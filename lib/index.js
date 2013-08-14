/**
 * Module dependencies.
 */
var Strategy = require('./strategy')
  , AuthorizationError = require('./errors/authorizationerror')
  , AccessTokenError = require('./errors/accesstokenerror')
  , InternalOAuthError = require('./errors/internaloautherror');


/**
 * Expose `Strategy` directly from package.
 */
exports = module.exports = Strategy;

/**
 * Export constructors.
 */
exports.Strategy = Strategy;

/**
 * Export errors.
 */
exports.AuthorizationError = AuthorizationError;
exports.AccessTokenError = AccessTokenError;
exports.InternalOAuthError = InternalOAuthError;
