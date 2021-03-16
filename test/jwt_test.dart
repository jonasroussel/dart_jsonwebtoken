import 'dart:convert';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:dart_jsonwebtoken/src/jwt.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:test/test.dart';
import 'package:uuid/uuid.dart';

List<int> _base64ToBytes(String encoded) {
  encoded += List.filled((4 - encoded.length % 4) % 4, '=').join();
  return base64Url.decode(encoded);
}

void main() {
  test('JWT Examples from RFC8037', () {
    String token;

    var d = _base64ToBytes('nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A');
    var x = _base64ToBytes('11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo');
    var privateKeyBytes = <int>[];
    privateKeyBytes.addAll(d);
    privateKeyBytes.addAll(x);
    var publicKey = EdDSAPublicKey(x);
    var privateKey = EdDSAPrivateKey(privateKeyBytes);
    {
      final jwt = JWT('Example of Ed25519 signing');

      token = jwt.sign(privateKey,
          algorithm: JWTAlgorithm.Ed25519, noIssueAt: true);

      print('Signed token: $token\n');
      expect(token,
          'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg');
    }

    try {
      final jwt = JWT.verify(token, publicKey);

      print('Payload: ${jwt.payload}');
    } on JWTExpiredError {
      print('jwt expired');
    } on JWTError catch (ex) {
      print(ex.message); // ex: invalid signature
    }
  });

  test('test sign & verify', () {
    var keyPair = ed.generateKey();
    var public = EdDSAPublicKey(keyPair.publicKey!.bytes);
    var private = EdDSAPrivateKey(keyPair.privateKey!.bytes);
    final jwt = JWT({
      'uid': Uuid().v4(),
      'sid': Uuid().v4(),
      'iat': (DateTime.now().millisecondsSinceEpoch / 1000).floor(),
      'exp': (DateTime.now().add(Duration(days: 365)).millisecondsSinceEpoch /
              1000)
          .floor(),
      'jti': Uuid().v4(),
      'sig': Uuid().v4(),
      'scp': 'FULL',
    });

    var token = jwt.sign(private, algorithm: JWTAlgorithm.Ed25519);
    print('Signed token: $token\n');

    final verifiedJwt = JWT.verify(token, public);

    expect(jwt.payload, verifiedJwt.payload);
    print('VerifiedJwt Payload: ${verifiedJwt.payload}');
  });
}
