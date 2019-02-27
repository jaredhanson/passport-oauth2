// Load modules.
const Strategy = require('./strategy');


const AuthorizationError = require('./errors/authorizationerror');


const TokenError = require('./errors/tokenerror');


const InternalOAuthError = require('./errors/internaloautherror');

Strategy.Strategy = Strategy;
Strategy.AuthorizationError = AuthorizationError;
Strategy.TokenError = TokenError;
Strategy.InternalOAuthError = InternalOAuthError;

module.exports = Strategy;
