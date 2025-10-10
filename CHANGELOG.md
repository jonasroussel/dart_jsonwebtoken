## 3.3.0

- Increase `JWT.payload` strictness (https://github.com/jonasroussel/dart_jsonwebtoken/issues/67)

## 3.2.0

- Update upper bound of pointycastle (https://github.com/jonasroussel/dart_jsonwebtoken/pull/65)
- Dart SDK minimum version set to 3.0.0
- Use `pointycastle` for HMAC calculation instead of `crypto`
- Implement custom deep list equality instead of using the `collection` package

## 3.1.1

- Rollback `collection` to 1.17.1 to be compatible with older flutter versions

## 3.1.0

- Fix unconsistant JWK convertion
- Add `JWTKey.fromJWK` static method for parsing JWK to various key types

## 3.0.0

- Possible **BREAKING CHANGE**: `exp`, `nbf` and `iat` are now following the JWT RFC for NumericDate by only using UTC DateTime
- Add JWK (JSON Web Key) conversion methods to key classes (`toJWK()`)
- Fix HMAC secret auto detect if base64 is url or not
- Fix base64Url instead of base64 for string payloads JWT
- Add header tests for `exp`, `nbf` and `iat`

## 2.17.0

- Parse standard parameters when using `JWT.decode` (https://github.com/jonasroussel/dart_jsonwebtoken/pull/64)

## 2.16.0

- Add support of PEM parsing for EdDSA keys with `EdDSAPrivateKey.fromPem` and `EdDSAPublicKey.fromPem`

## 2.15.0

- Added support for PSS alogrithm varations (https://github.com/jonasroussel/dart_jsonwebtoken/pull/59)

## 2.14.2

- Ensure `sub`, `iss`, `jti` are strings (https://github.com/jonasroussel/dart_jsonwebtoken/pull/62)

## 2.14.1

- Fix `iat` claim verification (https://github.com/jonasroussel/dart_jsonwebtoken/pull/57)

## 2.14.0

- Add support for base64 encoded secrets (https://github.com/jonasroussel/dart_jsonwebtoken/pull/54)
- Fix `exp`, `nbf` and `iat` checks by casting the value to `int`

## 2.13.0

- Fix invalid ECDSA signature for keys that are not a multiple of 8 (e.g. secp521r1) (https://github.com/jonasroussel/dart_jsonwebtoken/issues/51)

## 2.12.2

- Add testable date times (https://github.com/jonasroussel/dart_jsonwebtoken/issues/50)

## 2.12.1

- Fixing issue with custom headers (https://github.com/jonasroussel/dart_jsonwebtoken/issues/48)

## 2.12.0

- **NEW:** tests have been added
- **NEW:** publish & test CI
- Making all `JWTAlgorithm` classes public (mainly to be mocked in tests)

## 2.11.0

- Removing `basic_utils` package that was incompatible with flutter web
- Moving utils to `helpers.dart` and key parsing functions into `key_parser.dart`
- Adding some new examples in `example/example.dart`

## 2.10.0

- New ECDSA algorithm (ES256K)
- New RSA algorithm with PSS padding (PS256, PS384, PS512)
- README.md improved
- example/example.dart improved

## 2.9.1

- Adding a new class factory `ECPublicKey.cert`

## 2.9.0

- Adding `basic_utils` package to handle PEM & key parsing
- A lot of new class factory to create `Keys` (e.g. `RSAPublicKey.cert` and `.bytes`)

## 2.8.2

- Downgraing `collection` to 1.7.1 to be compatible with flutter_test

## 2.8.1

- Updating dependencies
- Fixing `CHANGELOG.md`

## 2.8.0

- **BREAKING CHANGE**: Replacing all JWTError by JWTException that is more accurate (https://github.com/jonasroussel/dart_jsonwebtoken/issues/39)
- Fixing assert message (https://github.com/jonasroussel/dart_jsonwebtoken/pull/42)

## 2.7.1

- Migrating from `pedantic` to `lints`

## 2.7.0

- `parsing.dart` has been replaced by more accurate CryptoUtils functions `https://github.com/Ephenodrom/Dart-Basic-Utils`
- Fixing `_ECDSAAlgorithm.sign` method that did not filling the gap in the ECDSA curve signatures

## 2.6.4

- Fixing `ECPrivateKey.raw` initialize `size`

## 2.6.3

- Adding a `.raw` and `.clone` constructor to `JWTKey` (execpt `SecretKey` of course)

## 2.6.2

- Fix rethrow of JWTError exceptions for the method `verify`. Before this change every exception thrown by `verify` always returned JWTUndefinedError

## 2.6.1

- Adding a `try` version of `decode`, `verify` and `sign`, that simply returns `null` instead of throwing errors

## 2.6.0

- Adding a `JWT.decode` method to simply decode a token without checking its signature
- The `JWT.verify` method do not remove extra token infos (`iss`, `aud`, ...) anymore

## 2.5.1

- Fix Flutter compatibility issue: `downgrade` dependency collection to `1.16.0`

## 2.5.0

- https://github.com/jonasroussel/dart_jsonwebtoken/commit/12348776259ccec70ccf62856ec0245f49ebe951

## 2.4.2

- Formating for 'static analysis'

## 2.4.1

- Fix : https://github.com/jonasroussel/dart_jsonwebtoken/issues/19

## 2.4.0

- **BREAKING CHANGE**: `JWT.audience` is now an instance of the `Audience` class, to handle multiple audience entries and can be used like list. You can always use a single entry by calling `Audience.one('...')` factory and the `.first` getter
- Upgrading `pointycastle` dependency to `3.3.4`

## 2.3.2

- Some badges on `README.md` (Thanks to https://github.com/bruno-garcia/badges.bar)

## 2.3.1

- Fix the `pointycastle` dependency, `v3.1.3` is incompatible with flutter web (dart2js)
  (https://github.com/jonasroussel/dart_jsonwebtoken/issues/14)

## 2.3.0

- Adding `header` in JWT class (you can now set your custom header)

## 2.2.0

- Fixing EdDSA incompatibility's with flutter web (https://github.com/jonasroussel/dart_jsonwebtoken/issues/11)
- Dependencies: `ed25519_edwards` have been removed, `convert` & `collection` have been added

## 2.1.1

- Fixing `_pkcs8ECPublicKey` to work with pointycastle 3.0.1

## 2.1.0

- When an undefined error occur `JWTUndefinedError` is thrown containing the original error in `error` property (https://github.com/jonasroussel/dart_jsonwebtoken/issues/9)
- **BREAKING CHANGE**: `jwt.verify` no longer support `throwUndefinedErrors` parameter

## 2.0.1

- Fixing `JWT.sign` to include `iat` & other attributes when payload is an empty Map

## 2.0.0

- Stable release for null safety

## 2.0.0-nullsafety.2

- New EdDSA Algorithm (EdDSA)
- EdDSAPrivateKey and EdDSAPublicKey, two new keys for EdDSA algorithm
- `ed25519_edwards` package has been added

## 2.0.0-nullsafety.1

- Null safety migration of this package

## 1.6.2

- Adding `analysis_options.yaml` to work with pedantic during development

## 1.6.1

- Formating for 'static analysis'

## 1.6.0

- New ECDSA Algorithm (ES256, ES384, ES512)
- ECPrivateKey and ECPublicKey, two new keys for ECDSA algorithm
- PrivateKey is renamed in RSAPrivateKey
- PublicKey is renamed in RSAPublicKey
- Optimization of private & public keys parsing
- `rsa_pkcs` & `cryptography` have been removed

## 1.5.0

- Debuging `_TypeError issue on sign method` (#4)
- Implementing `toString` in the `JWTError` class

## 1.4.1

- Formating for 'static analysis'

## 1.4.0

- Implementing `throwUndefinedErrors` option in the `JWT.verify` method

## 1.3.1

- Formating for 'static analysis'

## 1.3.0

- Adding checks in `JWT.verify` function for `iss, sub, aud, iat, jti`

## 1.2.1

- Formating for 'static analysis'

## 1.2.0

- Payload is now required
- Payload is now dynamic and not restricted to an object
- Dependencies updated

## 1.1.0

- New algorithms

## 1.0.3

- Formating for 'static analysis'

## 1.0.2

- Docs & examples

## 1.0.1

- More details on exceptions
- New examples

## 1.0.0

- New RSA Algorithm (RS256)
- Keys a now using an abstract class 'Key' instead of a string
- SecretKey: for HMAC (HS256)
- PrivateKey & PublicKey: for RSA (RS256)

## 0.2.1

- Formatting

## 0.2.0

- Better documentations

## 0.1.0

- First version with every based features
