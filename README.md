# JsonWebToken
[![pub package](https://img.shields.io/pub/v/dart_jsonwebtoken.svg)](https://pub.dev/packages/dart_jsonwebtoken)

A dart implementation of the famous javascript library `jsonwebtoken`.

## Usage

### Import
```dart
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
```

### Sign

```dart
// Create a json web token
final jwt = JWT(
  payload: {
    'id': 123,
    'server': {
      'id': '3e4fc296',
      'loc': 'euw-2',
    }
  },
  issuer: 'https://github.com/jonasroussel/jsonwebtoken',
);

// Sign it
token = jwt.sign('secret-key');

print('Signed token: $token\n');
```

### Verify

```dart
try {
  // Verify a token
  final jwt = JWT.verify(token, 'secret-key');

  print('Payload: ${jwt.payload}');
} on JWTExpiredError {
  print('jwt expired');
} on JWTError catch (ex) {
  print(ex.message); // ex: invalid signature
}
```
