var uid = require('uid2')
  , crypto = require('crypto');

/**
 * Creates an instance of `TokenStateProvider`.
 *
 * The token state provider is useful if you want to use OAuth state verification
 * without using session state on the client. It's also useful if you users take
 * longer than your session timeout to complete the OAuth login.
 *
 * Options:
 *
 *   - `passphrase`         A passphrase used for encrypting tokens. Make sure it's secure.
 *   - `cipher`             The cipher to use for encryption. Defaults to `aes128`.
 *   - `maxTokenAge`        The maximum age, in seconds, for a token before it's rejected. Defaults to one day.
 *
 * @constructor
 * @param {Object} options
 * @api public
 */
function TokenStateProvider(options) {
  if (!options.passphrase) { throw new TypeError('TokenStateProvider requires a passphrase'); }
  this._passphrase = options.passphrase;
  this._cipher = options.cipher || 'aes128';
  this._maxTokenAge = (options.maxTokenAge || 86400) * 1000;
}

/**
 * Generates a token using a random salt and the time.
 *
 * @param {Object} req
 * @param {Function} callback
 * @api protected
 */
TokenStateProvider.prototype.get = function(req, callback) {
  /* random = Salt + time */
  var random = uid(4) + ':' + Date.now().toString(16);

  var cipher = crypto.createCipher(this._cipher, this._passphrase);
  var state = cipher.update(random, 'ascii', 'hex') + cipher.final('hex');

  callback(null, state);
};

/**
 * Given a request, and the state returned by the OAuth provider, verifies the state.
 *
 * The state is decrypted using the passphrase, resulting in a salt plus the time.
 * Additionally, the time is validated to ensure that the time does not exceed the
 * bounds of [now - `maxTokenAge`..now + 60 seconds]
 *
 * The 60 second buffer on the time allows tokens to be generated on different servers in a
 * cluster which may have varing times, although if there's a 60 second difference you
 * may want to consider sorting out your `ntpd` issues first.
 *
 * @param {Object} req
 * @param {String} providedState
 * @param {Function} callback
 * @api protected
 */
TokenStateProvider.prototype.verify = function(req, providedState, callback) {
  if (!providedState) { return callback({ message: 'Invalid authorization request state.' }, 403); }

  try {
    var decipher = crypto.createDecipher(this._cipher, this._passphrase);
    var decrypted = decipher.update(providedState, 'hex', 'ascii') + decipher.final('ascii');

    if (this._verifyDecrypted(decrypted)) {
      return callback();
    } else {
      return callback({ message: 'Invalid authorization request state.' }, 403);
    }

  } catch(e) {
    return callback({ message: 'Invalid authorization request state.' }, 403);
  }
};

/**
 * Verify that a successfully decrypted token is valid.
 *
 * @param {String} decrypted
 * @api private
 */
TokenStateProvider.prototype._verifyDecrypted = function(decrypted) {
  var parts = decrypted.split(':', 2);
  if (parts[0].length !== 4) { return false; }
  var generatedAt = parseInt(parts[1], 16);
  var now = Date.now();

  return generatedAt &&
    generatedAt > now - this._maxTokenAge &&
    generatedAt < now + 60000; /* Allow for server clock skew */
};

/**
 * Expose `TokenStateProvider`.
 */
module.exports = TokenStateProvider;
