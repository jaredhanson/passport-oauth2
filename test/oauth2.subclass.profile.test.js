/* global describe, it, before, expect */
/* eslint-disable no-unused-expressions, consistent-return */


const chai = require('chai');
const util = require('util');
const OAuth2Strategy = require('../lib/strategy');


describe('OAuth2Strategy subclass', () => {
  describe('that overrides userProfile', () => {
    function FooOAuth2Strategy(options, verify) {
      OAuth2Strategy.call(this, options, verify);
    }
    util.inherits(FooOAuth2Strategy, OAuth2Strategy);

    FooOAuth2Strategy.prototype.userProfile = function userProfile(accessToken, done) {
      if (accessToken === '666') { return done(new Error('something went wrong loading user profile')); }

      if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }

      return done(null, { username: 'jaredhanson', location: 'Oakland, CA' });
    };


    describe('fetching user profile', () => {
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
        if (profile.username !== 'jaredhanson') { return done(new Error('incorrect profile argument')); }

        return done(null, { id: '1234', username: profile.username }, { message: 'Hello' });
      }));

      strategy._oauth2.getOAuthAccessToken = function getOAuthAccessToken(code, options, callback) {
        if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
        if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
        if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }

        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
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
          .authenticate();
      });

      it('should supply user', () => {
        expect(user).to.be.an('object');
        expect(user.id).to.equal('1234');
        expect(user.username).to.equal('jaredhanson');
      });

      it('should supply info', () => {
        expect(info).to.be.an('object');
        expect(info.message).to.equal('Hello');
      });
    }); // fetching user profile

    describe('error fetching user profile', () => {
      const strategy = new FooOAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      ((accessToken, refreshToken, profile, done) => done(new Error('verify callback should not be called'))));

      strategy._oauth2.getOAuthAccessToken = function getOAuthAccessToken(code, options, callback) {
        if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
        if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
        if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }

        return callback(null, '666', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
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
        expect(err.message).to.equal('something went wrong loading user profile');
      });
    }); // error fetching user profile

    describe('skipping user profile due to skipUserProfile option set to true', () => {
      const strategy = new FooOAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        skipUserProfile: true
      },
      ((accessToken, refreshToken, profile, done) => {
        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
        if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
        if (profile !== undefined) { return done(new Error('incorrect profile argument')); }

        return done(null, { id: '1234' }, { message: 'Hello' });
      }));

      strategy._oauth2.getOAuthAccessToken = function getOuathAccessToken(code, options, callback) {
        if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
        if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
        if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }

        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
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
    }); // skipping user profile due to skipUserProfile option set to true

    describe('not skipping user profile due to skipUserProfile returning false', () => {
      const strategy = new FooOAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        skipUserProfile() {
          return false;
        }
      },
      ((accessToken, refreshToken, profile, done) => {
        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
        if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
        if (profile.username !== 'jaredhanson') { return done(new Error('incorrect profile argument')); }

        return done(null, { id: '1234', username: profile.username }, { message: 'Hello' });
      }));

      strategy._oauth2.getOAuthAccessToken = function getOauthAccessToken(code, options, callback) {
        if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
        if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
        if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }

        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
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
          .authenticate();
      });

      it('should supply user', () => {
        expect(user).to.be.an('object');
        expect(user.id).to.equal('1234');
        expect(user.username).to.equal('jaredhanson');
      });

      it('should supply info', () => {
        expect(info).to.be.an('object');
        expect(info.message).to.equal('Hello');
      });
    }); // not skipping user profile due to skipUserProfile returning false

    describe('skipping user profile due to skipUserProfile returning true', () => {
      const strategy = new FooOAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        skipUserProfile() {
          return true;
        }
      },
      ((accessToken, refreshToken, profile, done) => {
        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
        if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
        if (profile !== undefined) { return done(new Error('incorrect profile argument')); }

        return done(null, { id: '1234' }, { message: 'Hello' });
      }));

      strategy._oauth2.getOAuthAccessToken = function getOAuthAccessToken(code, options, callback) {
        if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
        if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
        if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }

        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
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
    }); // skipping user profile due to skipUserProfile returning true

    describe('not skipping user profile due to skipUserProfile asynchronously returning false', () => {
      const strategy = new FooOAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        skipUserProfile(accessToken, done) {
          if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect token argument')); }

          return done(null, false);
        }
      },
      ((accessToken, refreshToken, profile, done) => {
        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
        if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
        if (profile.username !== 'jaredhanson') { return done(new Error('incorrect profile argument')); }

        return done(null, { id: '1234', username: profile.username }, { message: 'Hello' });
      }));

      strategy._oauth2.getOAuthAccessToken = function getOAuthAccessToken(code, options, callback) {
        if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
        if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
        if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }

        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
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
          .authenticate();
      });

      it('should supply user', () => {
        expect(user).to.be.an('object');
        expect(user.id).to.equal('1234');
        expect(user.username).to.equal('jaredhanson');
      });

      it('should supply info', () => {
        expect(info).to.be.an('object');
        expect(info.message).to.equal('Hello');
      });
    }); // not skipping user profile due to skipUserProfile asynchronously returning false

    describe('skipping user profile due to skipUserProfile asynchronously returning true', () => {
      const strategy = new FooOAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        skipUserProfile(accessToken, done) {
          if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect token argument')); }

          return done(null, true);
        }
      },
      ((accessToken, refreshToken, profile, done) => {
        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
        if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
        if (profile !== undefined) { return done(new Error('incorrect profile argument')); }

        return done(null, { id: '1234' }, { message: 'Hello' });
      }));

      strategy._oauth2.getOAuthAccessToken = function getOAuthAccessToken(code, options, callback) {
        if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
        if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
        if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }

        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
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
    }); // skipping user profile due to skipUserProfile asynchronously returning true

    describe('error due to skipUserProfile asynchronously returning error', () => {
      const strategy = new FooOAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
        skipUserProfile(accessToken, done) {
          return done(new Error('something went wrong'));
        }
      },
      ((accessToken, refreshToken, profile, done) => {
        if (accessToken !== '2YotnFZFEjr1zCsicMWpAA') { return done(new Error('incorrect accessToken argument')); }
        if (refreshToken !== 'tGzv3JOkF0XG5Qx2TlKWIA') { return done(new Error('incorrect refreshToken argument')); }
        if (profile !== undefined) { return done(new Error('incorrect profile argument')); }

        return done(null, { id: '1234' }, { message: 'Hello' });
      }));

      strategy._oauth2.getOAuthAccessToken = function getOAuthAccessToken(code, options, callback) {
        if (code !== 'SplxlOBeZQQYbYS6WxSbIA') { return callback(new Error('incorrect code argument')); }
        if (options.grant_type !== 'authorization_code') { return callback(new Error('incorrect options.grant_type argument')); }
        if (options.redirect_uri !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect options.redirect_uri argument')); }

        return callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example' });
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
        expect(err.message).to.equal('something went wrong');
      });
    }); // error due to skipUserProfile asynchronously returning error
  }); // that overrides userProfile
});
