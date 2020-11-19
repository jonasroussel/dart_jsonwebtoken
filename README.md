# JSON Web Token (JWT)
[![pub package](https://img.shields.io/pub/v/dart_jsonwebtoken.svg)](https://pub.dev/packages/dart_jsonwebtoken)

A dart implementation of the famous javascript library `jsonwebtoken`.

JSON Web Tokens are an open, industry standard RFC 7519 method for representing claims securely between two parties.
https://jwt.io allows you to decode, verify and generate JWT.

## Usage

### Import
```dart
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
```

### Sign

```dart
// Create a json web token
final jwt = JWT(
  {
    'id': 123,
    'server': {
      'id': '3e4fc296',
      'loc': 'euw-2',
    }
  },
  issuer: 'https://github.com/jonasroussel/jsonwebtoken',
);

// Sign it (default with HS256 algorithm)
token = jwt.sign(SecretKey('secret passphrase'));

print('Signed token: $token\n');
```

### Verify

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

- HS256 (HMAC / SHA256)
- HS384 (HMAC / SHA384)
- HS512 (HMAC / SHA512)

- RS256 (RSA / SHA256)
- RS384 (RSA / SHA384)
- RS512 (RSA / SHA512)
