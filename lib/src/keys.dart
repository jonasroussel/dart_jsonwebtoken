import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:dart_jsonwebtoken/src/utils.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:pointycastle/pointycastle.dart' as pc;

import 'exceptions.dart';

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
  RSAPrivateKey.bytes(Uint8List bytes)
      : key = CryptoUtils.rsaPrivateKeyFromDERBytes(bytes);
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
  RSAPublicKey.bytes(Uint8List bytes) {
    try {
      key = CryptoUtils.rsaPublicKeyFromDERBytesPkcs1(bytes);
    } catch (_) {
      key = CryptoUtils.rsaPublicKeyFromDERBytes(bytes);
    }
  }
  RSAPublicKey.cert(String pem) {
    final x509 = X509Utils.x509CertificateFromPem(pem);
    final bytes = x509.tbsCertificate?.subjectPublicKeyInfo.bytes;
    if (bytes == null) {
      throw JWTParseException('x509 Certificate parsing failed');
    }

    try {
      key = CryptoUtils.rsaPublicKeyFromDERBytesPkcs1(hexToUint8List(bytes));
    } catch (_) {
      key = CryptoUtils.rsaPublicKeyFromDERBytes(hexToUint8List(bytes));
    }
  }
}

/// For ECDSA algorithm, in sign method
class ECPrivateKey extends JWTKey {
  late pc.ECPrivateKey key;
  late int size;

  ECPrivateKey(String pem) {
    final _key = CryptoUtils.ecPrivateKeyFromPem(pem);
    final _params = _key.parameters;

    if (_params == null) {
      throw JWTParseException('ECPrivateKey parameters are invalid');
    }

    key = _key;
    size = (_params.curve.fieldSize / 8).round();
  }

  ECPrivateKey.raw(pc.ECPrivateKey _key) {
    final _params = _key.parameters;

    if (_params == null) {
      throw JWTParseException('ECPrivateKey parameters are invalid');
    }

    key = _key;
    size = (_params.curve.fieldSize / 8).round();
  }
  ECPrivateKey.clone(ECPrivateKey _key)
      : key = _key.key,
        size = _key.size;
  ECPrivateKey.bytes(Uint8List bytes)
      : key = CryptoUtils.ecPrivateKeyFromDerBytes(bytes);
}

/// For ECDSA algorithm, in verify method
class ECPublicKey extends JWTKey {
  late pc.ECPublicKey key;

  ECPublicKey(String pem) {
    key = CryptoUtils.ecPublicKeyFromPem(pem);
  }

  ECPublicKey.raw(pc.ECPublicKey _key) : key = _key;
  ECPublicKey.clone(ECPublicKey _key) : key = _key.key;
  ECPublicKey.bytes(Uint8List bytes)
      : key = CryptoUtils.ecPublicKeyFromDerBytes(bytes);
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
