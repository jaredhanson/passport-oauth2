/**
 * `AuthorizationError` error.
 *
 * AuthorizationError represents an error in response to an authorization
 * request.  For details, refer to RFC 6749, section 4.1.2.1.
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

class AuthorizationError extends Error {
  constructor(message, code, uri, status) {
    super(message);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, AuthorizationError);
    }
    if (!status) {
      switch (code) {
        case 'access_denied': status = 403; break;
        case 'server_error': status = 502; break;
        case 'temporarily_unavailable': status = 503; break;
        default: status = 500;
      }
    }

    this.code = code || 'server_error';
    this.uri = uri;
    this.status = status;
    this.name = 'AuthorizationError';
  }
}

module.exports = AuthorizationError;
