# passport-oauth2

General-purpose OAuth 2.0 authentication strategy for [Passport](https://www.passportjs.org/).

This module lets you authenticate using OAuth 2.0 in your Node.js applications.
By plugging into Passport, OAuth 2.0-based sign in can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](https://github.com/senchalabs/connect#readme)-style middleware, including
[Express](https://expressjs.com/).

Note that this strategy provides generic OAuth 2.0 support.  In many cases, a
provider-specific strategy can be used instead, which cuts down on unnecessary
configuration, and accommodates any provider-specific quirks.  See the
[list](https://github.com/jaredhanson/passport/wiki/Strategies) for supported
providers.

Developers who need to implement authentication against an OAuth 2.0 provider
that is not already supported are encouraged to sub-class this strategy.  If you
choose to open source the new provider-specific strategy, please add it to the
list so other people can find it.

<div align="center">

:brain: [Understanding OAuth 2.0](https://www.passportjs.org/concepts/oauth2/?utm_source=github&utm_medium=referral&utm_campaign=passport-oauth2&utm_content=nav-concept) •
:heart: [Sponsors](https://www.passportjs.org/sponsors/?utm_source=github&utm_medium=referral&utm_campaign=passport-oauth2&utm_content=nav-sponsors)

</div>

---

<p align="center">
  <sup>Advertisement</sup>
  <br>
  <a href="https://click.linksynergy.com/link?id=D*o7yui4/NM&offerid=507388.380582&type=2&murl=https%3A%2F%2Fwww.udemy.com%2Fcourse%2Flearn-oauth-2%2F&u1=5I2riUEiNIRjPjdjxj6X4exzu3lhRkWY0et6Y8eyT3">Learn OAuth 2.0 - Get started as an API Security Expert</a><br>Just imagine what could happen to YOUR professional career if you had skills in OAuth > 8500 satisfied students
</p>

---

[![npm](https://img.shields.io/npm/v/passport-oauth2.svg)](https://www.npmjs.com/package/passport-oauth2)
[![build](https://img.shields.io/travis/jaredhanson/passport-oauth2.svg)](https://travis-ci.org/jaredhanson/passport-oauth2)
[![coverage](https://img.shields.io/coveralls/jaredhanson/passport-oauth2.svg)](https://coveralls.io/github/jaredhanson/passport-oauth2)
[...](https://github.com/jaredhanson/passport-oauth2/wiki/Status)

## Install

    $ npm install passport-oauth2

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

## Related Modules

- [passport-oauth1](https://github.com/jaredhanson/passport-oauth1) — OAuth 1.0 authentication strategy
- [passport-http-bearer](https://github.com/jaredhanson/passport-http-bearer) — Bearer token authentication strategy for APIs
- [OAuth2orize](https://github.com/jaredhanson/oauth2orize) — OAuth 2.0 authorization server toolkit

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

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2011-2016 Jared Hanson <[http://jaredhanson.net/](http://jaredhanson.net/)>


