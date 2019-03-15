var chai = require('chai')
  , passport = require('chai-passport-strategy');

chai.use(passport);


global.$require = require('proxyquire');
global.expect = chai.expect;
