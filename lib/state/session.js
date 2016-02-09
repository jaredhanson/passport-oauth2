var uid = require('uid2');

/**
 * Creates an instance of `SessionStateProvider`.
 *
 * This is the default state provider implementation for the OAuth2Strategy.
 * If generates a random state and stores it in `req.session` under the `key`
 * provided in the constructor.
 *
 * If no session exists, the provider will throw an error. If you are not using
 * sessions, consider using `TokenStateProvider` instead.
 *
 * Options:
 *
 *   - `key`               The key in the session under which to store the session state
 *
 * @constructor
 * @param {Object} options
 * @api public
 */
function SessionStore(options) {
  if (!options.key) { throw new TypeError('SessionStateStore requires a key'); }
  this._key = options.key;
}

/**
 * Given a request, returns a value to use as state.
 *
 * This implementation simply generates a random UID and stores the value in the session
 * for validation at a later stage when `verify` is called.
 *
 * @param {Object} req
 * @param {Function} callback
 * @api protected
 */
SessionStore.prototype.store = function(req, callback) {
  if (!req.session) { return callback(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?')); }

  var key = this._key;
  var state = uid(24);
  if (!req.session[key]) { req.session[key] = {}; }
  req.session[key].state = state;
  callback(null, state);
};

/**
 * Given a request, and the state returned by the OAuth provider, verifies the state.
 *
 * This implementation simply compares the returned state to the one saved in the user's session.
 * If they do not match, or no state is saved in the session, the call will fail.
 * If there is no session, the call will return an error.
 *
 * The callback signature has two values (`err`, `failureCode`). On success, these are both
 * undefined. On error, only `err` is definied and on failure, err will contain the failure object
 * while `failureCode` will contain the failure code.
 *
 * @param {Object} req
 * @param {String} providedState
 * @param {Function} callback
 * @api protected
 */
SessionStore.prototype.verify = function(req, providedState, callback) {
  if (!req.session) { return callback(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?')); }

  var key = this._key;
  if (!req.session[key]) {
   return callback(null, false, { message: 'Unable to verify authorization request state.' });
  }

  var state = req.session[key].state;
  if (!state) {
   return callback(null, false, { message: 'Unable to verify authorization request state.' });
  }

  delete req.session[key].state;
  if (Object.keys(req.session[key]).length === 0) {
   delete req.session[key];
  }

  if (state !== providedState) {
   return callback(null, false, { message: 'Invalid authorization request state.' });
  }

  return callback(null, true);
};

/**
 * Expose `SessionStateProvider`.
 */
module.exports = SessionStore;
