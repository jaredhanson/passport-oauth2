/**
 * Module dependencies.
 */
var Strategy = require('./strategy')
  , AuthorizationError = require('./errors/authorizationerror')
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
exports.InternalOAuthError = InternalOAuthError;
