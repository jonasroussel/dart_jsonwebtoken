# JSON Web Token (JWT)

[![pub version](https://img.shields.io/pub/v/dart_jsonwebtoken.svg)](https://pub.dev/packages/dart_jsonwebtoken)

A dart implementation of the famous javascript library `jsonwebtoken`.

JSON Web Tokens are an open, industry standard RFC 7519 method for representing claims securely between two parties.

https://jwt.io allows you to decode, verify and generate JWT.

## Usage

### Import

```dart
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
```

### Creating & signing a JWT

```dart
// Create a json web token
// Pass the payload to be sent in the form of a map
final jwt = JWT(

  // Payload
  {
    'id': 123,

    'server': {
      'id': '3e4fc296',
      'loc': 'euw-2',
    }

  },

  issuer: 'https://github.com/jonasroussel/dart_jsonwebtoken',

);

// Sign it (default with HS256 algorithm)
token = jwt.sign(SecretKey('secret passphrase'));

print('Signed token: $token\n');
```

### Check if the JWT made is correct.

```dart
try {
  // Verify a token
  final jwt = JWT.verify(token, SecretKey('secret passphrase'));

  print('Payload: ${jwt.payload}');

} on JWTExpiredError {

  print('jwt expired');

} on JWTError catch (ex) {

  print(ex.message); // ex: invalid signature

}
```

### Supported Algorithms

| JWT Algorithms | Digital Signature or MAC Algorithm                   |
| -------------- | ---------------------------------------------------- |
| HS256          | HMAC using SHA-256 hash algorithm                    |
| HS384          | HMAC using SHA-384 hash algorithm                    |
| HS512          | HMAC using SHA-512 hash algorithm                    |
| RS256          | RSASSA-PKCS1-v1_5 using SHA-256 hash algorithm       |
| RS384          | RSASSA-PKCS1-v1_5 using SHA-384 hash algorithm       |
| RS512          | RSASSA-PKCS1-v1_5 using SHA-512 hash algorithm       |
| ES256          | ECDSA using P-256 curve and SHA-256 hash algorithm   |
| ES384          | ECDSA using P-384 curve and SHA-384 hash algorithm   |
| ES512          | ECDSA using P-521 curve and SHA-512 hash algorithm   |
| EdDSA          | EdDSA using ed25519 curve and SHA-512 hash algorithm |
