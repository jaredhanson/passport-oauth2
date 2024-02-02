# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.8.0] - 2024-02-02
### Fixed
- Fixed intermittent "Failed to obtain access token" error by updating `oauth`
dependency from 0.9.x to 0.10.x.  This error seems to occur more frequently on
fast connections which get reset after receiving an access token response.

## [1.7.0] - 2023-03-02
### Added

- Support for authorization response parameters encoded as HTML form values, as
specified by [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html).

## [1.6.1] - 2021-09-24
### Fixed
- Error in cases where the authorization server returns a successful access
token response which is missing an `access_token` parameter.

## [1.6.0] - 2021-07-01
### Added

- Support for `store: true` option to `Strategy` constructor, which initializes
a state store capable of storing application-level state.
- Support for `state` object passed as option to `authenticate`, which will be
persisted in the session by state store.
- `callbackURL` property added to metadata passed to state store.

[Unreleased]: https://github.com/jaredhanson/passport-oauth2/compare/v1.7.0...HEAD
[1.7.0]: https://github.com/jaredhanson/passport-oauth2/compare/v1.6.1...v1.7.0
