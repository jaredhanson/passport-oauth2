// Load modules.
const passport = require('@passport-next/passport-strategy');
const url = require('url');
const util = require('util');
const OAuth2 = require('oauth').OAuth2;
const utils = require('./utils');
const NullStateStore = require('./state/null');
const SessionStateStore = require('./state/session');
const AuthorizationError = require('./errors/authorizationerror');
const TokenError = require('./errors/tokenerror');
const InternalOAuthError = require('./errors/internaloautherror');


/**
 * Creates an instance of `OAuth2Strategy`.
 *
 * The OAuth 2.0 authentication strategy authenticates requests using the OAuth
 * 2.0 framework.
 *
 * OAuth 2.0 provides a facility for delegated authentication, whereby users can
 * authenticate using a third-party service such as Facebook.  Delegating in
 * this manner involves a sequence of events, including redirecting the user to
 * the third-party service for authorization.  Once authorization has been
 * granted, the user is redirected back to the application and an authorization
 * code can be used to obtain credentials.
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(accessToken, refreshToken, profile, done) { ... }
 *
 * The verify callback is responsible for finding or creating the user, and
 * invoking `done` with the following arguments:
 *
 *     done(err, user, info);
 *
 * `user` should be set to `false` to indicate an authentication failure.
 * Additional `info` can optionally be passed as a third argument, typically
 * used to display informational messages.  If an exception occured, `err`
 * should be set.
 *
 * Options:
 *
 *   - `authorizationURL`  URL used to obtain an authorization grant
 *   - `tokenURL`          URL used to obtain an access token
 *   - `clientID`          identifies client to service provider
 *   - `clientSecret`      secret used to establish ownership of the client identifer
 *   - `callbackURL`       URL to which the service provider will redirect the user after
 *   obtaining authorization
 *   - `passReqToCallback` when `true`, `req` is the first argument to the verify callback
 *   (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new OAuth2Strategy({
 *         authorizationURL: 'https://www.example.com/oauth2/authorize',
 *         tokenURL: 'https://www.example.com/oauth2/token',
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/example/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function OAuth2Strategy(options, verify) {
  if (typeof options === 'function') {
    verify = options;
    options = undefined;
  }
  options = options || {};

  if (!verify) { throw new TypeError('OAuth2Strategy requires a verify callback'); }
  if (!options.authorizationURL) { throw new TypeError('OAuth2Strategy requires a authorizationURL option'); }
  if (!options.tokenURL) { throw new TypeError('OAuth2Strategy requires a tokenURL option'); }
  if (!options.clientID) { throw new TypeError('OAuth2Strategy requires a clientID option'); }

  passport.Strategy.call(this);
  this.name = 'oauth2';
  this._verify = verify;

  // NOTE: The _oauth2 property is considered "protected".  Subclasses are
  //       allowed to use it when making protected resource requests to retrieve
  //       the user profile.
  this._oauth2 = new OAuth2(options.clientID, options.clientSecret,
    '', options.authorizationURL, options.tokenURL, options.customHeaders);

  this._callbackURL = options.callbackURL;
  this._scope = options.scope;
  this._scopeSeparator = options.scopeSeparator || ' ';
  this._responseType = options.responseType || 'code';
  this._key = options.sessionKey || (`oauth2:${url.parse(options.authorizationURL).hostname}`);

  if (options.store) {
    this._stateStore = options.store;
  } else if (options.state) {
    this._stateStore = new SessionStateStore({ key: this._key });
  } else {
    this._stateStore = new NullStateStore();
  }
  this._trustProxy = options.proxy;
  this._passReqToCallback = options.passReqToCallback;
  this._loadUserProfileFromIdToken = options.parseIdToken;
  this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;
}

// Inherit from `passport.Strategy`.
util.inherits(OAuth2Strategy, passport.Strategy);


/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
// eslint-disable-next-line consistent-return
OAuth2Strategy.prototype.authenticate = function authenticate(req, options) {
  options = options || {};
  const self = this;
  let callbackURL = options.callbackURL || this._callbackURL;
  // eslint-disable-next-line consistent-return
  function loaded(err, ok, state) {
    if (err) { return self.error(err); }
    if (!ok) {
      return self.fail(state, 403);
    }

    const code = req.query.code;

    const params = self.tokenParams(options);
    params.grant_type = 'authorization_code';
    if (callbackURL) { params.redirect_uri = callbackURL; }

    self._oauth2.getOAuthAccessToken(code, params,
      // eslint-disable-next-line consistent-return
      (tokenErr, accessToken, refreshToken, tokenParams) => {
        if (tokenErr) {
          return self.error(
            self._createOAuthError('Failed to obtain access token', tokenErr)
          );
        }

        self._loadUserProfile(accessToken, tokenParams, (profileErr, profile) => {
          if (profileErr) { return self.error(profileErr); }

          function verified(verifiedErr, user, info) {
            if (verifiedErr) { return self.error(verifiedErr); }
            if (!user) { return self.fail(info); }

            info = info || {};
            if (state) { info.state = state; }
            return self.success(user, info);
          }

          try {
            const arity = self._verify.length;
            if (self._passReqToCallback) {
              if (arity === 6) {
                return self._verify(req, accessToken, refreshToken, tokenParams, profile, verified);
              } // arity == 5
              return self._verify(req, accessToken, refreshToken, profile, verified);
            }
            if (arity === 5) {
              return self._verify(accessToken, refreshToken, tokenParams, profile, verified);
            } // arity == 4
            return self._verify(accessToken, refreshToken, profile, verified);
          } catch (ex) {
            return self.error(ex);
          }
        });
      });
  }
  if (req.query && req.query.error) {
    if (req.query.error === 'access_denied') {
      return this.fail({ message: req.query.error_description });
    }
    return this.error(
      new AuthorizationError(
        req.query.error_description, req.query.error, req.query.error_uri
      )
    );
  }

  const responseType = options.responseType || this._responseType;
  if (callbackURL) {
    const parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
    }
  }

  const meta = {
    authorizationURL: this._oauth2._authorizeUrl,
    tokenURL: this._oauth2._accessTokenUrl,
    clientID: this._oauth2._clientId
  };

  if (req.query && req.query.code) {
    try {
      const state = req.query.state;
      const arity = this._stateStore.verify.length;
      if (arity === 4) {
        this._stateStore.verify(req, state, meta, loaded);
      } else { // arity == 3
        this._stateStore.verify(req, state, loaded);
      }
    } catch (ex) {
      return this.error(ex);
    }
  } else {
    const params = this.authorizationParams(options);
    // eslint-disable-next-line no-inner-declarations
    function stored(err, state) {
      if (err) { return self.error(err); }

      if (state) { params.state = state; }
      const parsed = url.parse(self._oauth2._authorizeUrl, true);
      utils.merge(parsed.query, params);
      parsed.query.client_id = self._oauth2._clientId;
      delete parsed.search;
      const location = url.format(parsed);
      return self.redirect(location);
    }

    params.response_type = responseType;
    if (callbackURL) { params.redirect_uri = callbackURL; }

    let scope;
    if (this._scope && options.scope) {
      scope = [].concat(options.scope).concat(this._scope);
    } else {
      scope = this._scope || options.scope;
    }

    if (scope) {
      if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
      params.scope = scope;
    }

    const state = options.state;
    if (state) {
      params.state = state;

      const parsed = url.parse(this._oauth2._authorizeUrl, true);
      utils.merge(parsed.query, params);
      parsed.query.client_id = this._oauth2._clientId;
      delete parsed.search;
      const location = url.format(parsed);
      this.redirect(location);
    } else {
      try {
        const arity = this._stateStore.store.length;
        if (arity === 3) {
          this._stateStore.store(req, meta, stored);
        } else { // arity == 2
          this._stateStore.store(req, stored);
        }
      } catch (ex) {
        return this.error(ex);
      }
    }
  }
};

/**
 * Retrieve user profile from service provider.
 *
 * OAuth 2.0-based authentication strategies can overrride this function in
 * order to load the user's profile from the service provider.  This assists
 * applications (and users of those applications) in the initial registration
 * process by automatically submitting required information.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
OAuth2Strategy.prototype.userProfile = function userProfile(accessToken, done) {
  return done(null, {});
};

/**
 * Return extra parameters to be included in the authorization request.
 *
 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
 * included when requesting authorization.  Since these parameters are not
 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
 * strategies can overrride this function in order to populate these parameters
 * as required by the provider.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
OAuth2Strategy.prototype.authorizationParams = function authorizationParams() {
  return {};
};

/**
 * Return extra parameters to be included in the token request.
 *
 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
 * included when requesting an access token.  Since these parameters are not
 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
 * strategies can overrride this function in order to populate these parameters
 * as required by the provider.
 *
 * @return {Object}
 * @api protected
 */
OAuth2Strategy.prototype.tokenParams = function tokenParams() {
  return {};
};

/**
 * Parse error response from OAuth 2.0 endpoint.
 *
 * OAuth 2.0-based authentication strategies can overrride this function in
 * order to parse error responses received from the token endpoint, allowing the
 * most informative message to be displayed.
 *
 * If this function is not overridden, the body will be parsed in accordance
 * with RFC 6749, section 5.2.
 *
 * @param {String} body
 * @param {Number} status
 * @return {Error}
 * @api protected
 */
OAuth2Strategy.prototype.parseErrorResponse = function parseErrorResponse(body) {
  const json = JSON.parse(body);
  if (json.error) {
    return new TokenError(json.error_description, json.error, json.error_uri);
  }
  return null;
};

/**
 * Load user profile, contingent upon options.
 *
 * @param {String} accessToken
 * @param {Object} params
 * @param {Function} done
 * @api private
 */
OAuth2Strategy.prototype._loadUserProfile = function _loadUserProfile(accessToken, params, done) {
  const self = this;

  function loadIt() {
    if (self._loadUserProfileFromIdToken && params.id_token) {
      return self.userProfile(params.id_token, done);
    }
    return self.userProfile(accessToken, done);
  }
  function skipIt() {
    return done(null);
  }

  if (typeof this._skipUserProfile === 'function' && this._skipUserProfile.length > 1) {
    // async
    return this._skipUserProfile(accessToken, (err, skip) => {
      if (err) { return done(err); }
      if (!skip) { return loadIt(); }
      return skipIt();
    });
  }
  const skip = (typeof this._skipUserProfile === 'function') ? this._skipUserProfile() : this._skipUserProfile;
  if (!skip) { return loadIt(); }
  return skipIt();
};

/**
 * Create an OAuth error.
 *
 * @param {String} message
 * @param {Object|Error} err
 * @api private
 */
OAuth2Strategy.prototype._createOAuthError = function _createOAuthError(message, err) {
  let e;
  if (err.statusCode && err.data) {
    try {
      e = this.parseErrorResponse(err.data, err.statusCode);
    // eslint-disable-next-line no-empty
    } catch (_) {}
  }
  if (!e) { e = new InternalOAuthError(message, err); }
  return e;
};


// Expose constructor.
module.exports = OAuth2Strategy;
