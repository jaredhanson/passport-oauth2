# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.0] - 2021-07-01
### Added

- Support for `state: true` option to `Strategy` constructor, which initializes
a state store capable of storing application-level state.
- Support for `state` object passed as option to `authenticate`, which will be
persisted in the session by state store.
- `callbackURL` property added to metadata passed to state store.
