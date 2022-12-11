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

- New ECDSA Algorithm (EC256, EC384, EC512)
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
