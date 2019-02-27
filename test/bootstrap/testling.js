/* global window */
const chai = require('chai');


const passport = require('chai-passport-strategy');

chai.use(passport);


window.expect = chai.expect;
