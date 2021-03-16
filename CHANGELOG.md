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
