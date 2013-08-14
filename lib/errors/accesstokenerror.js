/**
 * `AccessTokenError` error.
 *
 * AccessTokenError represents an error in response to an access token request.
 * For details, refer to RFC 6749, section 5.2.
 *
 * References:
 *   - [The OAuth 2.0 Authorization Framework](http://tools.ietf.org/html/rfc6749)
 *
 * @constructor
 * @param {String} [message]
 * @param {String} [code]
 * @param {String} [uri]
 * @param {Number} [status]
 * @api public
 */
function AccessTokenError(message, code, uri, status) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'AccessTokenError';
  this.message = message;
  this.code = code || 'invalid_request';
  this.uri = uri;
  this.status = status || 500;
}

/**
 * Inherit from `Error`.
 */
AccessTokenError.prototype.__proto__ = Error.prototype;


/**
 * Expose `AccessTokenError`.
 */
module.exports = AccessTokenError;
