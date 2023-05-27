import 'dart:io';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

void main() {
  print('----- HMAC SHA-256 ------');
  hs256();
  print('-------------------------\n');

  print('----- RSA SHA-256 -----');
  rs256();
  print('-----------------------\n');

  print('----- ECDSA SHA-256 -----');
  es256();
  print('-------------------------');
}

// HMAC SHA-256 algorithm
void hs256() {
  String token;

  /* Sign */ {
    // Create a json web token
    final jwt = JWT(
      {
        'id': 123,
        'server': {
          'id': '3e4fc296',
          'loc': 'euw-2',
        }
      },
      issuer: 'https://github.com/jonasroussel/dart_jsonwebtoken',
    );

    // Sign it
    token = jwt.sign(SecretKey('secret passphrase'));

    print('Signed token: $token\n');
  }

  /* Verify */ {
    try {
      // Verify a token
      final jwt = JWT.verify(token, SecretKey('secret passphrase'));

      print('Payload: ${jwt.payload}');
    } on JWTExpiredException {
      print('jwt expired');
    } on JWTException catch (ex) {
      print(ex.message); // ex: invalid signature
    }
  }
}

// RSA SHA-256 algorithm
void rs256() {
  String token;

  /* Sign */ {
    // Create a json web token
    final jwt = JWT(
      {
        'id': 123,
        'server': {
          'id': '3e4fc296',
          'loc': 'euw-2',
        }
      },
      issuer: 'https://github.com/jonasroussel/dart_jsonwebtoken',
    );

    // Sign it
    final pem = File('./example/rsa_private.pem').readAsStringSync();
    final key = RSAPrivateKey(pem);

    token = jwt.sign(key, algorithm: JWTAlgorithm.RS256);

    print('Signed token: $token\n');
  }

  /* Verify */ {
    try {
      // Verify a token
      final pem = File('./example/rsa_public.pem').readAsStringSync();
      final key = RSAPublicKey(pem);

      final jwt = JWT.verify(token, key);

      print('Payload: ${jwt.payload}');
    } on JWTExpiredException {
      print('jwt expired');
    } on JWTException catch (ex) {
      print(ex.message); // ex: invalid signature
    }
  }
}

// ECDSA SHA-256 algorithm
void es256() {
  String token;

  /* Sign */ {
    // Create a json web token
    final jwt = JWT(
      {
        'id': 123,
        'server': {
          'id': '3e4fc296',
          'loc': 'euw-2',
        }
      },
      issuer: 'https://github.com/jonasroussel/dart_jsonwebtoken',
    );

    // Sign it
    final pem = File('./example/ec_private.pem').readAsStringSync();
    final key = ECPrivateKey(pem);

    token = jwt.sign(key, algorithm: JWTAlgorithm.ES256);

    print('Signed token: $token\n');
  }

  /* Verify */ {
    try {
      // Verify a token
      final pem = File('./example/ec_public.pem').readAsStringSync();
      final key = ECPublicKey(pem);

      final jwt = JWT.verify(token, key);

      print('Payload: ${jwt.payload}');
    } on JWTExpiredException {
      print('jwt expired');
    } on JWTException catch (ex) {
      print(ex.message); // ex: invalid signature
    }
  }
}
