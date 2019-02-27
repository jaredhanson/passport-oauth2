const chai = require('chai');


const passport = require('chai-passport-strategy');

chai.use(passport);


global.expect = chai.expect;
