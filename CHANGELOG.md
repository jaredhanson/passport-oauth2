# 2.0.3 (2019-08-27)

* Updated npm deps

# 2.0.2 (2019-07-13)

### Patch

* Updated deps to fix security issue with lodash [here](https://github.com/lodash/lodash/pull/4336) @rwky

# 2.0.1 (2019-06-12)

### Patch

* Updated deps to fix security issues with js-yaml [here](https://github.com/nodeca/js-yaml/issues/475) and [here](https://github.com/nodeca/js-yaml/pull/480) @rwky
* Updated travis to support node 12 and remove support for node 6 and 11 @rwky

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

### Patch

* Updated npm deps @rwky

# 1.7.0 (2018-07-07)

### Minor

* Support scopes defined both in strategy constructor and authenticate call. @anabellaspinelli

### Patch

* Updated loadash dep for security https://nodesecurity.io/advisories/577 @rwky

# 1.6.0 (2018-07-07)

### Minor

* Added responseType as parameter defaults to 'code' @jeffersonpenna

### Patch

* Updated README.md @dan-nl

# 1.5.0 (2018-06-29)
    
### Initial commit

* Added CHANGELOG.md @rwky
* Updated travis to use node 6, 8 and 10 @rwky
* Removed uid2 dep replaced with node crypto @rwky
* Replaced utils-merge with lodash
* Updated README.md and package.json for passport-next org

