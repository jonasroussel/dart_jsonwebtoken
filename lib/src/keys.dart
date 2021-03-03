import 'package:pointycastle/pointycastle.dart' as pc;

import 'errors.dart';
import 'parser.dart';

abstract class Key {}

/// For HMAC algorithms
class SecretKey extends Key {
  String key;

  SecretKey(this.key);
}

/// For RSA algorithm, in sign method
class RSAPrivateKey extends Key {
  late pc.RSAPrivateKey key;

  RSAPrivateKey(String pem) {
    final _key = parseRSAPrivateKeyPEM(pem);
    if (_key == null) throw JWTParseError('RSAPrivateKey is invalid');
    key = _key;
  }
}

/// For RSA algorithm, in verify method
class RSAPublicKey extends Key {
  late pc.RSAPublicKey key;

  RSAPublicKey(String pem) {
    final _key = parseRSAPublicKeyPEM(pem);
    if (_key == null) throw JWTParseError('RSAPublicKey is invalid');
    key = _key;
  }
}

/// For ECDSA algorithm, in sign method
class ECPrivateKey extends Key {
  late pc.ECPrivateKey key;
  late int size;

  ECPrivateKey(String pem) {
    final _key = parseECPrivateKeyPEM(pem);
    final _params = _key?.parameters;

    if (_key == null) throw JWTParseError('ECPrivateKey is invalid');
    if (_params == null) {
      throw JWTParseError('ECPrivateKey parameters are invalid');
    }

    key = _key;
    size = (_params.curve.fieldSize / 8).round();
  }
}

/// For ECDSA algorithm, in verify method
class ECPublicKey extends Key {
  late pc.ECPublicKey key;

  ECPublicKey(String pem) {
    final _key = parseECPublicKeyPEM(pem);
    if (_key == null) throw JWTParseError('ECPublicKey is invalid');
    key = _key;
  }
}
