# passport-oauth2

[![Build Status](https://travis-ci.org/passport-next/passport-oauth2.svg?branch=master)](https://travis-ci.org/passport-next/passport-oauth2)
[![Coverage Status](https://coveralls.io/repos/github/passport-next/passport-oauth2/badge.svg?branch=master)](https://coveralls.io/github/passport-next/passport-oauth2?branch=master)
[![Maintainability](https://api.codeclimate.com/v1/badges/e6a0d9379adb9283308a/maintainability)](https://codeclimate.com/github/passport-next/passport-oauth2/maintainability)
[![Dependencies](https://david-dm.org/passport-next/passport-oauth2.png)](https://david-dm.org/passport-next/passport-oauth2)
<!--[![SAST](https://gitlab.com/passport-next/passport-oauth2/badges/master/build.svg)](https://gitlab.com/passport-next/passport-oauth2/badges/master/build.svg)-->

General-purpose OAuth 2.0 authentication strategy for [Passport](http://passportjs.org/).

This module lets you authenticate using OAuth 2.0 in your Node.js applications.
By plugging into Passport, OAuth 2.0 authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

Note that this strategy provides generic OAuth 2.0 support.  In many cases, a
provider-specific strategy can be used instead, which cuts down on unnecessary
configuration, and accommodates any provider-specific quirks.  See the
[list](https://github.com/jaredhanson/passport/wiki/Strategies) for supported
providers.

Developers who need to implement authentication against an OAuth 2.0 provider
that is not already supported are encouraged to sub-class this strategy.  If you
choose to open source the new provider-specific strategy, please add it to the
list so other people can find it.

## Install

    $ npm install @passport-next/passport-oauth2

## Usage

#### Configure Strategy

The OAuth 2.0 authentication strategy authenticates users using a third-party
account and OAuth 2.0 tokens.  The provider's OAuth 2.0 endpoints, as well as
the client identifer and secret, are specified as options.  The strategy
requires a `verify` callback, which receives an access token and profile,
and calls `cb` providing a user.

```js
passport.use(new OAuth2Strategy({
    authorizationURL: 'https://www.example.com/oauth2/authorize',
    tokenURL: 'https://www.example.com/oauth2/token',
    clientID: EXAMPLE_CLIENT_ID,
    clientSecret: EXAMPLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/example/callback"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ exampleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
```

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'oauth2'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

```js
app.get('/auth/example',
  passport.authenticate('oauth2'));

app.get('/auth/example/callback',
  passport.authenticate('oauth2', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
  });
```

## Strategy Options

#### authorizationURL
REQUIRED<br>
`{ authorizationURL: string }`<br>
URL used to obtain an authorization grant

#### tokenURL
REQUIRED<br>
`{ tokenURL: string }`<br>
URL used to obtain an access token

#### clientID
REQUIRED<br>
`{ clientID: string }`<br>
The client identifier issued to the client by the OAuth 2.0 service.

#### clientSecret
REQUIRED<br>
`{ clientSecret: string }`<br>
The client secret issued to the client by the OAuth 2.0 service.

#### callbackURL
OPTIONAL<br>
`{ callbackURL: string }`<br>
URL to which the service provider will redirect the user after obtaining authorization. The URL can be relative or fully qualified; when relative, the original URL of the authorization request will be prepended to the relative URL.

#### customHeaders
OPTIONAL<br>
`{ customHeaders: Object }`<br>
Custom headers you can pass along with the authorization request.

#### passReqToCallback
OPTIONAL<br>
`{ passReqToCallback: boolean }`<br>
When set to `true`, the first argument sent to the verify callback is the request, `http.IncomingMessage`, (default: `false`)

#### proxy
OPTIONAL<br>
`{ proxy: boolean }`<br>
Used when resolving a relative callbackURL. When set to `true`, `req.headers['x-forwarded-proto']` and `req.headers['x-forwarded-host']` will be used otherwise `req.connection.encrypted` and `req.headers.host` will be used.

_Note_: if your webserver, e.g. `Express`, provides `req.app.get` and the value `req.app.get('trust proxy')` is set, proxy option will automatically be set to `true`.

#### scope
OPTIONAL<br>
`{ scope: Array|string }`<br>
The scope of the access request made by the client of the OAuth 2.0 service. The scope is a list one or more strings, which are defined by the OAuth 2.0 service.

When the scope is provided as a list of strings, each string should be separated by a single space, as per the OAuth 2.0 spec. When the scope is provided as an Array of strings, each array element will be joined by the scopeSeparator.

#### scopeSeparator
OPTIONAL<br>
`{ scopeSeparator: string }`<br>
The separator used to join the scope strings when the `scope` is provided as an Array (default: `single space`).

#### sessionKey
OPTIONAL<br>
`{ sessionKey: string }`<br>
The key to use to store the state string when the `state` option is set to `true`. (default: 'oauth2:' + url.parse(options.authorizationURL).hostname)

#### skipUserProfile
OPTIONAL<br>
`{ skipUserProfile: boolean }`<br>
Whether or not to return the user profile information of the user granting authorization to their account information.

#### state
OPTIONAL<br>
`{ state: boolean }`<br>
When set to `true`, a state string with be created, stored, sent along with the authentication request and verified when the response from the OAuth 2.0 service is received.

#### store
OPTIONAL<br>
`{ store: Function }`<br>
The store to use when storing the state string (default: `SessionStore`, `req.session[sessionKey]`, requires session middleware such as `express-session`). See the [NullStore](lib/state/null.js) for an example of a store function.

## Contributing

#### Tests

The test suite is located in the `test/` directory.  All new features are
expected to have corresponding test cases.  Ensure that the complete test suite
passes by executing:

```bash
$ make test
```

#### Coverage

All new feature development is expected to have test coverage.  Patches that
increse test coverage are happily accepted.  Coverage reports can be viewed by
executing:

```bash
$ make test-cov
$ make view-cov
```
