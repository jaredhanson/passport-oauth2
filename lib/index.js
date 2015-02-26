/**
 * Module dependencies.
 */
var Strategy = require('./strategy')
  , SessionStateProvider = require('./sessionstateprovider')
  , TokenStateProvider = require('./tokenstateprovider')
  , AuthorizationError = require('./errors/authorizationerror')
  , TokenError = require('./errors/tokenerror')
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
 * Export the state providers
 */
exports.SessionStateProvider = SessionStateProvider;
exports.TokenStateProvider = TokenStateProvider;

/**
 * Export errors.
 */
exports.AuthorizationError = AuthorizationError;
exports.TokenError = TokenError;
exports.InternalOAuthError = InternalOAuthError;
