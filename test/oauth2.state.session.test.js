/* global describe, it, before, expect */
/* eslint-disable no-unused-expressions, consistent-return */
const chai = require('chai');
const uri = require('url');
const OAuth2Strategy = require('../lib/strategy');

describe('OAuth2Strategy', () => {
  describe('using default session state store', () => {
    describe('issuing authorization request', () => {
      const strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        state: true
      },
      (() => {}));


      describe('that redirects to service provider', () => {
        let request; let
          url;

        before((done) => {
          chai.passport.use(strategy)
            .redirect((u) => {
              url = u;
              done();
            })
            .req((req) => {
              request = req;
              req.session = {};
            })
            .authenticate();
        });

        it('should be redirected', () => {
          const u = uri.parse(url, true);
          expect(u.query.state).to.have.length(32);
        });

        it('should save state in session', () => {
          const u = uri.parse(url, true);

          expect(request.session['oauth2:www.example.com'].state).to.have.length(32);
          expect(request.session['oauth2:www.example.com'].state).to.equal(u.query.state);
        });
      }); // that redirects to service provider

      describe('that redirects to service provider with other data in session', () => {
        let request; let
          url;

        before((done) => {
          chai.passport.use(strategy)
            .redirect((u) => {
              url = u;
              done();
            })
            .req((req) => {
              request = req;
              req.session = {};
              req.session['oauth2:www.example.com'] = {};
              req.session['oauth2:www.example.com'].foo = 'bar';
            })
            .authenticate();
        });

        it('should be redirected', () => {
          const u = uri.parse(url, true);
          expect(u.query.state).to.have.length(32);
        });

        it('should save state in session', () => {
          const u = uri.parse(url, true);

          expect(request.session['oauth2:www.example.com'].state).to.have.length(32);
          expect(request.session['oauth2:www.example.com'].state).to.equal(u.query.state);
        });

        it('should preserve other data in session', () => {
          expect(request.session['oauth2:www.example.com'].foo).to.equal('bar');
        });
      }); // that redirects to service provider with other data in session

      describe('that errors due to lack of session support in app', () => {
        let err;

        before((done) => {
          chai.passport.use(strategy)
            .error((e) => {
              err = e;
              done();
            })
            .req(() => {
            })
            .authenticate();
        });

        it('should error', () => {
          expect(err).to.be.an.instanceof(Error);
          expect(err.message).to.equal('OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?');
        });
      }); // that errors due to lack of session support in app
    }); // issuing authorization request

    describe('issuing authorization request to authorization server using authorization endpoint that has query parameters including state', () => {
      const strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize?foo=bar&state=baz',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        state: true
      },
      (() => {}));


      describe('that redirects to service provider', () => {
        let request; let
          url;

        before((done) => {
          chai.passport.use(strategy)
            .redirect((u) => {
              url = u;
              done();
            })
            .req((req) => {
              request = req;
              req.session = {};
            })
            .authenticate();
        });

        it('should be redirected', () => {
          const u = uri.parse(url, true);
          expect(u.query.foo).equal('bar');
          expect(u.query.state).to.have.length(32);
        });

        it('should save state in session', () => {
          const u = uri.parse(url, true);

          expect(request.session['oauth2:www.example.com'].state).to.have.length(32);
          expect(request.session['oauth2:www.example.com'].state).to.equal(u.query.state);
        });
      }); // that redirects to service provider
    }); /* issuing authorization request to authorization server using authorization
      endpoint that has query parameters including state */

    describe('processing response to authorization request', () => {
      const strategy = new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        state: true
      },
      ((accessToken, refreshToken, profile, done) => {
        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
        if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
        if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
        if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }

        return done(null, { id: '1234' }, { message: 'Hello' });
      }));

      strategy._oauth2.getOAuthAccessToken = function getOAuthAccessToken(code, options, callback) {
        if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
        if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
        if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }

        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
      };


      describe('that was approved', () => {
        let request;


        let user;


        let info;

        before((done) => {
          chai.passport.use(strategy)
            .success((u, i) => {
              user = u;
              info = i;
              done();
            })
            .req((req) => {
              request = req;

              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.session = {};
              req.session['oauth2:www.example.com'] = {};
              req.session['oauth2:www.example.com'].state = 'DkbychwKu8kBaJoLE5yeR5NK';
            })
            .authenticate();
        });

        it('should supply user', () => {
          expect(user).to.be.an('object');
          expect(user.id).to.equal('1234');
        });

        it('should supply info', () => {
          expect(info).to.be.an('object');
          expect(info.message).to.equal('Hello');
        });

        it('should remove state from session', () => {
          expect(request.session['oauth2:www.example.com']).to.be.undefined;
        });
      }); // that was approved

      describe('that was approved with other data in the session', () => {
        let request;


        let user;


        let info;

        before((done) => {
          chai.passport.use(strategy)
            .success((u, i) => {
              user = u;
              info = i;
              done();
            })
            .req((req) => {
              request = req;

              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.session = {};
              req.session['oauth2:www.example.com'] = {};
              req.session['oauth2:www.example.com'].state = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.session['oauth2:www.example.com'].foo = 'bar';
            })
            .authenticate();
        });

        it('should supply user', () => {
          expect(user).to.be.an('object');
          expect(user.id).to.equal('1234');
        });

        it('should supply info', () => {
          expect(info).to.be.an('object');
          expect(info.message).to.equal('Hello');
        });

        it('should preserve other data from session', () => {
          expect(request.session['oauth2:www.example.com'].state).to.be.undefined;
          expect(request.session['oauth2:www.example.com'].foo).to.equal('bar');
        });
      }); // that was approved with other data in the session

      describe('that fails due to state being invalid', () => {
        let request;


        let info;


        let status;

        before((done) => {
          chai.passport.use(strategy)
            .fail((i, s) => {
              info = i;
              status = s;
              done();
            })
            .req((req) => {
              request = req;

              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK-WRONG';
              req.session = {};
              req.session['oauth2:www.example.com'] = {};
              req.session['oauth2:www.example.com'].state = 'DkbychwKu8kBaJoLE5yeR5NK';
            })
            .authenticate();
        });

        it('should supply info', () => {
          expect(info).to.be.an('object');
          expect(info.message).to.equal('Invalid authorization request state.');
        });

        it('should supply status', () => {
          expect(status).to.equal(403);
        });

        it('should remove state from session', () => {
          expect(request.session['oauth2:www.example.com']).to.be.undefined;
        });
      }); // that fails due to state being invalid

      describe('that fails due to provider-specific state not found in session', () => {
        let info;
        let status;

        before((done) => {
          chai.passport.use(strategy)
            .fail((i, s) => {
              info = i;
              status = s;
              done();
            })
            .req((req) => {
              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.session = {};
            })
            .authenticate();
        });

        it('should supply info', () => {
          expect(info).to.be.an('object');
          expect(info.message).to.equal('Unable to verify authorization request state.');
        });

        it('should supply status', () => {
          expect(status).to.equal(403);
        });
      }); // that fails due to state not found in session

      describe('that fails due to provider-specific state lacking state value', () => {
        let info;
        let status;

        before((done) => {
          chai.passport.use(strategy)
            .fail((i, s) => {
              info = i;
              status = s;
              done();
            })
            .req((req) => {
              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.session = {};
              req.session['oauth2:www.example.com'] = {};
            })
            .authenticate();
        });

        it('should supply info', () => {
          expect(info).to.be.an('object');
          expect(info.message).to.equal('Unable to verify authorization request state.');
        });

        it('should supply status', () => {
          expect(status).to.equal(403);
        });
      }); // that fails due to provider-specific state lacking state value

      describe('that errors due to lack of session support in app', () => {
        let err;

        before((done) => {
          chai.passport.use(strategy)
            .error((e) => {
              err = e;
              done();
            })
            .req((req) => {
              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
            })
            .authenticate();
        });

        it('should error', () => {
          expect(err).to.be.an.instanceof(Error);
          expect(err.message).to.equal('OAuth 2.0 authentication requires session support when using state. Did you forget to use express-session middleware?');
        });
      }); // that errors due to lack of session support in app
    }); // processing response to authorization request
  }); // using default session state store


  describe('using default session state store with session key option', () => {
    const strategy = new OAuth2Strategy({
      authorizationURL: 'https://www.example.com/oauth2/authorize',
      tokenURL: 'https://www.example.com/oauth2/token',
      clientID: 'ABC123',
      clientSecret: 'secret',
      callbackURL: 'https://www.example.net/auth/example/callback',
      state: true,
      sessionKey: 'oauth2:example'
    },
    ((accessToken, refreshToken, profile, done) => {
      if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
      if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
      if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
      if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }

      return done(null, { id: '1234' }, { message: 'Hello' });
    }));

    strategy._oauth2.getOAuthAccessToken = function getOAuthAccessToken(code, options, callback) {
      if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
      if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
      if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }

      return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
    };


    describe('issuing authorization request', () => {
      describe('that redirects to service provider', () => {
        let request; let
          url;

        before((done) => {
          chai.passport.use(strategy)
            .redirect((u) => {
              url = u;
              done();
            })
            .req((req) => {
              request = req;
              req.session = {};
            })
            .authenticate();
        });

        it('should be redirected', () => {
          const u = uri.parse(url, true);
          expect(u.query.state).to.have.length(32);
        });

        it('should save state in session', () => {
          const u = uri.parse(url, true);

          expect(request.session['oauth2:example'].state).to.have.length(32);
          expect(request.session['oauth2:example'].state).to.equal(u.query.state);
        });
      }); // that redirects to service provider
    }); // issuing authorization request

    describe('processing response to authorization request', () => {
      describe('that was approved', () => {
        let request;


        let user;


        let info;

        before((done) => {
          chai.passport.use(strategy)
            .success((u, i) => {
              user = u;
              info = i;
              done();
            })
            .req((req) => {
              request = req;

              req.query = {};
              req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
              req.query.state = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.session = {};
              req.session['oauth2:example'] = {};
              req.session['oauth2:example'].state = 'DkbychwKu8kBaJoLE5yeR5NK';
            })
            .authenticate();
        });

        it('should supply user', () => {
          expect(user).to.be.an('object');
          expect(user.id).to.equal('1234');
        });

        it('should supply info', () => {
          expect(info).to.be.an('object');
          expect(info.message).to.equal('Hello');
        });

        it('should remove state from session', () => {
          expect(request.session['oauth2:example']).to.be.undefined;
        });
      }); // that was approved
    }); // processing response to authorization request
  }); // using default session state store with session key option
});
