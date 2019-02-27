/* global describe, it, before, expect */
/* eslint-disable no-unused-expressions, consistent-return */
const chai = require('chai');
const util = require('util');
const OAuth2Strategy = require('../lib/strategy');
const InternalOAuthError = require('../lib/errors/internaloautherror');

describe('OAuth2Strategy subclass', () => {
  describe('that overrides authorizationParams', () => {
    function FooOAuth2Strategy(options, verify) {
      OAuth2Strategy.call(this, options, verify);
    }
    util.inherits(FooOAuth2Strategy, OAuth2Strategy);

    FooOAuth2Strategy.prototype.authorizationParams = function authorizationParams(options) {
      return { prompt: options.prompt };
    };


    describe('issuing authorization request that redirects to service provider', () => {
      const strategy = new FooOAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      ((accessToken, refreshToken, profile, done) => {
        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
        if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }

        return done(null, { id: '1234' }, { message: 'Hello' });
      }));


      describe('with prompt', () => {
        let url;

        before((done) => {
          chai.passport.use(strategy)
            .redirect((u) => {
              url = u;
              done();
            })
            .req(() => {
            })
            .authenticate({ prompt: 'mobile' });
        });

        it('should be redirected', () => {
          expect(url).to.equal('https://www.example.com/oauth2/authorize?prompt=mobile&response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123');
        });
      }); // with prompt

      describe('with scope and prompt', () => {
        let url;

        before((done) => {
          chai.passport.use(strategy)
            .redirect((u) => {
              url = u;
              done();
            })
            .req(() => {
            })
            .authenticate({ scope: 'email', prompt: 'mobile' });
        });

        it('should be redirected', () => {
          expect(url).to.equal('https://www.example.com/oauth2/authorize?prompt=mobile&response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&scope=email&client_id=ABC123');
        });
      }); // with scope and prompt
    }); // issuing authorization request that redirects to service provider
  }); // that overrides authorizationParams


  describe('that overrides tokenParams', () => {
    function FooOAuth2Strategy(options, verify) {
      OAuth2Strategy.call(this, options, verify);
    }
    util.inherits(FooOAuth2Strategy, OAuth2Strategy);

    FooOAuth2Strategy.prototype.tokenParams = function tokenParams(options) {
      return { type: options.type };
    };


    describe('processing response to authorization request that was approved', () => {
      const strategy = new FooOAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      ((accessToken, refreshToken, profile, done) => {
        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
        if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }

        return done(null, { id: '1234' }, { message: 'Hello' });
      }));

      strategy._oauth2.getOAuthAccessToken = function getOAuthAccessToken(code, options, callback) {
        if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
        if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
        if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }
        if (options.type !== 'web_server') { return callback(new Error('incorrect options.type argument')); }

        callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
      };


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
            req.query = {};
            req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
          })
          .authenticate({ type: 'web_server' });
      });

      it('should supply user', () => {
        expect(user).to.be.an('object');
        expect(user.id).to.equal('1234');
      });

      it('should supply info', () => {
        expect(info).to.be.an('object');
        expect(info.message).to.equal('Hello');
      });
    }); // processing response to authorization request that was approved
  }); // that overrides tokenParams


  describe('that overrides parseErrorResponse', () => {
    function FooOAuth2Strategy(options, verify) {
      OAuth2Strategy.call(this, options, verify);
    }
    util.inherits(FooOAuth2Strategy, OAuth2Strategy);

    FooOAuth2Strategy.prototype.parseErrorResponse = function parseErrorResponse(body, status) {
      if (status === 500) { throw new Error('something went horribly wrong'); }

      const e = new Error('Custom OAuth error');
      e.body = body;
      e.status = status;
      return e;
    };


    describe('and supplies error', () => {
      const strategy = new FooOAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      ((accessToken, refreshToken, profile, done) => {
        if (accessToken === '2YotnFZFEjr1zCsicMWpAA' && refreshToken === 'tGzv3JOkF0XG5Qx2TlKWIA') {
          return done(null, { id: '1234' }, { message: 'Hello' });
        }
        return done(null, false);
      }));

      strategy._oauth2.getOAuthAccessToken = function getOAuthAccessToken(code, options, callback) {
        return callback({ statusCode: 400, data: 'Invalid code' });
      };


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
          })
          .authenticate();
      });

      it('should error', () => {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('Custom OAuth error');
        expect(err.body).to.equal('Invalid code');
        expect(err.status).to.equal(400);
      });
    }); // and supplies error

    describe('and throws exception', () => {
      const strategy = new FooOAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      ((accessToken, refreshToken, profile, done) => {
        if (accessToken === '2YotnFZFEjr1zCsicMWpAA' && refreshToken === 'tGzv3JOkF0XG5Qx2TlKWIA') {
          return done(null, { id: '1234' }, { message: 'Hello' });
        }
        return done(null, false);
      }));

      strategy._oauth2.getOAuthAccessToken = function getOAuthAccessToken(code, options, callback) {
        return callback({ statusCode: 500, data: 'Invalid code' });
      };


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
          })
          .authenticate();
      });

      it('should error', () => {
        expect(err).to.be.an.instanceof(InternalOAuthError);
        expect(err.message).to.equal('Failed to obtain access token');
        expect(err.oauthError.statusCode).to.equal(500);
        expect(err.oauthError.data).to.equal('Invalid code');
      });
    }); // and throws exception
  }); // that overrides parseErrorResponse
});
