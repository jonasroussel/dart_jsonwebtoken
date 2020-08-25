import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

main() {
  String token;

  /* Sign */ {
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
    token = jwt.sign(SecretKey('secret passphrase'));

    print('Signed token: $token\n');
  }

  /* Verify */ {
    try {
      // Verify a token
      final jwt = JWT.verify(token, SecretKey('secret passphrase'));

      print('Payload: ${jwt.payload}');
    } on JWTExpiredError {
      print('jwt expired');
    } on JWTError catch (ex) {
      print(ex.message); // ex: invalid signature
    }
  }
}
