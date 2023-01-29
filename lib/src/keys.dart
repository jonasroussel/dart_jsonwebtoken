import 'package:pointycastle/pointycastle.dart' as pc;

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'errors.dart';
import 'crypto_utils.dart';

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
    if (pem.startsWith(CryptoUtils.BEGIN_RSA_PRIVATE_KEY)) {
      key = CryptoUtils.rsaPrivateKeyFromPemPkcs1(pem);
    } else {
      key = CryptoUtils.rsaPrivateKeyFromPem(pem);
    }
  }

  RSAPrivateKey.raw(pc.RSAPrivateKey _key) : key = _key;
  RSAPrivateKey.clone(RSAPrivateKey _key) : key = _key.key;
}

/// For RSA algorithm, in verify method
class RSAPublicKey extends JWTKey {
  late pc.RSAPublicKey key;

  RSAPublicKey(String pem) {
    if (pem.startsWith(CryptoUtils.BEGIN_RSA_PUBLIC_KEY)) {
      key = CryptoUtils.rsaPublicKeyFromPemPkcs1(pem);
    } else {
      key = CryptoUtils.rsaPublicKeyFromPem(pem);
    }
  }

  RSAPublicKey.raw(pc.RSAPublicKey _key) : key = _key;
  RSAPublicKey.clone(RSAPublicKey _key) : key = _key.key;
}

/// For ECDSA algorithm, in sign method
class ECPrivateKey extends JWTKey {
  late pc.ECPrivateKey key;
  late int size;

  ECPrivateKey(String pem) {
    final _key = CryptoUtils.ecPrivateKeyFromPem(pem);
    final _params = _key.parameters;

    if (_params == null) {
      throw JWTParseError('ECPrivateKey parameters are invalid');
    }

    key = _key;
    size = (_params.curve.fieldSize / 8).round();
  }

  ECPrivateKey.raw(pc.ECPrivateKey _key) {
    final _params = _key.parameters;

    if (_params == null) {
      throw JWTParseError('ECPrivateKey parameters are invalid');
    }

    key = _key;
    size = (_params.curve.fieldSize / 8).round();
  }
  ECPrivateKey.clone(ECPrivateKey _key)
      : key = _key.key,
        size = _key.size;
}

/// For ECDSA algorithm, in verify method
class ECPublicKey extends JWTKey {
  late pc.ECPublicKey key;

  ECPublicKey(String pem) {
    key = CryptoUtils.ecPublicKeyFromPem(pem);
  }

  ECPublicKey.raw(pc.ECPublicKey _key) : key = _key;
  ECPublicKey.clone(ECPublicKey _key) : key = _key.key;
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
