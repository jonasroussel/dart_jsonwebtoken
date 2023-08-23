# JSON Web Token (JWT)

[![pub version](https://img.shields.io/pub/v/dart_jsonwebtoken.svg)](https://pub.dev/packages/dart_jsonwebtoken)

A dart implementation of the famous javascript library `jsonwebtoken`.

JSON Web Tokens are an open, industry standard RFC 7519 method for representing claims securely between two parties.

https://jwt.io allows you to decode, verify and generate JWT.

## Examples

Check out the [Example File](https://github.com/jonasroussel/dart_jsonwebtoken/blob/main/example/example.dart) for a full example code of all the differents algorithms.

## Usage

### Import

```dart
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
```

### Creating & signing a JWT

```dart
// Generate a JSON Web Token
// You can provide the payload as a key-value map or a string
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
final token = jwt.sign(SecretKey('secret passphrase'));

print('Signed token: $token\n');
```

### Check if the JWT made is correct.

```dart
try {
  // Verify a token (SecretKey for HMAC & PublicKey for all the others)
  final jwt = JWT.verify(token, SecretKey('secret passphrase'));

  print('Payload: ${jwt.payload}');
} on JWTExpiredException {
  print('jwt expired');
} on JWTException catch (ex) {
  print(ex.message); // ex: invalid signature
}
```

### You can also, decode the token without checking its signature

```dart
final jwt = JWT.decode(token);

print('Payload: ${jwt.payload}');
```

### Keys creation for all the algorithms

The raw PEM content provided here is intended for learning purposes. In a production environment, it's recommended to read the private and public keys from separate files. Then, you can pass the content of these files (as strings) in the parameters

```dart
// H256, H384, H512
final hmacKey = SecretKey('secret passphrase');


// RS256, RS384, RS512, PS256, PS384, PS512
final rsaPrivKey = RSAPrivateKey('''
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAq5QLAv9kYTgelglIhC17KdfUoinkwvQ4F0TZAp7qgmu19dCx
...
-----END RSA PRIVATE KEY-----
''');

// You can also extract the public key from a certificate with RSAPublicKey.cert(...)
final rsaPubKey = RSAPublicKey('''
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq5QLAv9kYTgelglIhC17
...
-----END PUBLIC KEY-----
'''
);


// ES256, ES256K, ES384, ES512
final ecPrivKey = ECPrivateKey('''
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
...
-----END PRIVATE KEY-----
''');

// You can also extract the public key from a certificate with ECPublicKey.cert(...)
final ecPubKey = ECPublicKEy('''
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
...
-----END PUBLIC KEY-----
''');


// EdDSA (PEM parsing is not available for EdDSA keys)
final edPrivKey = EdDSAPrivateKey([1, 42, 12, 84, ...]);
final edPubKey = EdDSAPublicKey([1, 42, 12, 84, ...]);
```

### Supported Algorithms

| JWT Algorithms | Digital Signature or MAC Algorithm                    |
| -------------- | ----------------------------------------------------- |
| HS256          | HMAC using SHA-256 hash algorithm                     |
| HS384          | HMAC using SHA-384 hash algorithm                     |
| HS512          | HMAC using SHA-512 hash algorithm                     |
| PS256          | RSASSA-PSS using SHA-256 hash algorithm               |
| PS384          | RSASSA-PSS using SHA-384 hash algorithm               |
| PS512          | RSASSA-PSS using SHA-512 hash algorithm               |
| RS256          | RSASSA-PKCS1-v1_5 using SHA-256 hash algorithm        |
| RS384          | RSASSA-PKCS1-v1_5 using SHA-384 hash algorithm        |
| RS512          | RSASSA-PKCS1-v1_5 using SHA-512 hash algorithm        |
| ES256          | ECDSA using P-256 curve and SHA-256 hash algorithm    |
| ES256K         | ECDSA using secp256k curve and SHA-256 hash algorithm |
| ES384          | ECDSA using P-384 curve and SHA-384 hash algorithm    |
| ES512          | ECDSA using P-521 curve and SHA-512 hash algorithm    |
| EdDSA          | EdDSA using ed25519 curve and SHA-512 hash algorithm  |
