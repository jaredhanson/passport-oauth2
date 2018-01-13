var uid = require('uid2');


function SessionStore(options) {
  options = options || {};
  this._key = options.key || 'oauth2';
}

SessionStore.prototype.store = function(req, meta, callback) {
  if (!req.session) { return callback(new Error('OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?')); }

  var state = uid(24);
  var key = this._key + ':' + state;
  req.session[key] = meta.state || {};
  callback(null, state);
};

SessionStore.prototype.verify = function(req, providedState, callback) {
  if (!req.session) { return callback(new Error('OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?')); }

  var key = this._key + ':' + providedState;
  var state = req.session[key];
  if (!state) {
   return callback(null, false, { message: 'Unable to verify authorization request state.' });
  }
  
  delete req.session[key];
  
  return callback(null, true, state);
};

// Expose constructor.
module.exports = SessionStore;
