# 2.0.0 (2019-02-27)

### Major

* AuthorizationError, InternalOAuthError and TokenError now always have a `message` property
which will be an empty string if there is no message, previously this was `undefined` @rwky

### Patch

* Updated npm deps @rwky
* Added node 11 to travis @rwky
* Linted code using eslint #5 @rwky
* Added github templates @rwky

# 1.7.1 (2019-02-13)

* Updated npm deps @rwky

# 1.7.0 (2018-07-07)

* Support scopes defined both in strategy constructor and authenticate call. @anabellaspinelli
* Updated loadash dep for security https://nodesecurity.io/advisories/577 @rwky

# 1.6.0 (2018-07-07)

* Updated README.md @dan-nl
* Added responseType as parameter defaults to 'code' @jeffersonpenna

# 1.5.0 (2018-06-29)
    
* Added CHANGELOG.md @rwky
* Updated travis to use node 6, 8 and 10 @rwky
* Removed uid2 dep replaced with node crypto @rwky
* Replaced utils-merge with lodash
* Updated README.md and package.json for passport-next org
