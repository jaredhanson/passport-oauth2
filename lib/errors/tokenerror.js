/**
 * `TokenError` error.
 *
 * TokenError represents an error received from a token endpoint.  For details,
 * refer to RFC 6749, section 5.2.
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

class TokenError extends Error {
  constructor(message, code, uri, status) {
    super(message);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, TokenError);
    }
    this.code = code || 'invalid_request';
    this.uri = uri;
    this.status = status || 500;
    this.name = 'TokenError';
  }
}
module.exports = TokenError;
