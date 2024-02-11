import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:pointycastle/pointycastle.dart' as pc;

import 'exceptions.dart';
import 'key_parser.dart';

abstract class JWTKey {}

/// For HMAC algorithms
class SecretKey extends JWTKey {
  String key;

  SecretKey(this.key);
}

/// For RSA algorithm, in sign method
class RSAPrivateKey extends JWTKey {
  late pc.RSAPrivateKey key;

  RSAPrivateKey(String pem) {
    key = KeyParser.rsaPrivateKeyFromPEM(
      pem,
      pkcs1: pem.startsWith(KeyParser.BEGIN_RSA_PRIVATE_KEY),
    );
  }

  RSAPrivateKey.raw(pc.RSAPrivateKey _key) : key = _key;
  RSAPrivateKey.clone(RSAPrivateKey _key) : key = _key.key;
  RSAPrivateKey.bytes(Uint8List bytes) : key = KeyParser.rsaPrivateKey(bytes);
}

/// For RSA algorithm, in verify method
class RSAPublicKey extends JWTKey {
  late pc.RSAPublicKey key;

  RSAPublicKey(String pem) {
    key = KeyParser.rsaPublicKeyFromPEM(
      pem,
      pkcs1: pem.startsWith(KeyParser.BEGIN_RSA_PUBLIC_KEY),
    );
  }

  RSAPublicKey.raw(pc.RSAPublicKey _key) : key = _key;
  RSAPublicKey.clone(RSAPublicKey _key) : key = _key.key;
  RSAPublicKey.bytes(Uint8List bytes) {
    try {
      key = KeyParser.rsaPublicKey(bytes);
    } catch (_) {
      key = KeyParser.rsaPublicKeyPKCS1(bytes);
    }
  }
  RSAPublicKey.cert(String pem) {
    final bytes = KeyParser.publicKeyBytesFromCertificate(pem);

    key = RSAPublicKey.bytes(bytes).key;
  }
}

/// For ECDSA algorithm, in sign method
class ECPrivateKey extends JWTKey {
  late pc.ECPrivateKey key;
  late int size;

  ECPrivateKey(String pem) {
    final _key = KeyParser.ecPrivateKeyFromPEM(
      pem,
      pkcs1: pem.startsWith(KeyParser.BEGIN_EC_PRIVATE_KEY),
    );
    final _params = _key.parameters;

    if (_params == null) {
      throw JWTParseException('ECPrivateKey parameters are invalid');
    }

    key = _key;
    size = (_params.curve.fieldSize / 8).ceil();
  }

  ECPrivateKey.raw(pc.ECPrivateKey _key) {
    final _params = _key.parameters;

    if (_params == null) {
      throw JWTParseException('ECPrivateKey parameters are invalid');
    }

    key = _key;
    size = (_params.curve.fieldSize / 8).ceil();
  }
  ECPrivateKey.clone(ECPrivateKey _key)
      : key = _key.key,
        size = _key.size;
  ECPrivateKey.bytes(Uint8List bytes) : key = KeyParser.ecPrivateKey(bytes);
}

/// For ECDSA algorithm, in verify method
class ECPublicKey extends JWTKey {
  late pc.ECPublicKey key;

  ECPublicKey(String pem) {
    key = KeyParser.ecPublicKeyFromPEM(pem);
  }

  ECPublicKey.raw(pc.ECPublicKey _key) : key = _key;
  ECPublicKey.clone(ECPublicKey _key) : key = _key.key;
  ECPublicKey.bytes(Uint8List bytes) : key = KeyParser.ecPublicKey(bytes);
  ECPublicKey.cert(String pem) {
    final bytes = KeyParser.publicKeyBytesFromCertificate(pem);

    key = ECPublicKey.bytes(bytes).key;
  }
}

/// For EdDSA algorithm, in sign method
class EdDSAPrivateKey extends JWTKey {
  late ed.PrivateKey key;

  EdDSAPrivateKey(List<int> bytes) {
    key = ed.PrivateKey(bytes);
  }
}

/// For EdDSA algorithm, in verify method
class EdDSAPublicKey extends JWTKey {
  late ed.PublicKey key;

  EdDSAPublicKey(List<int> bytes) {
    key = ed.PublicKey(bytes);
  }
}
