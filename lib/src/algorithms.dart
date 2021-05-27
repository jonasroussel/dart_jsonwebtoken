import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:pointycastle/pointycastle.dart' as pc;

import 'ed25519/export.dart' as ed;
import 'errors.dart';
import 'keys.dart';
import 'utils.dart';

abstract class JWTAlgorithm {
  /// HMAC using SHA-256 hash algorithm
  static const HS256 = _HMACAlgorithm('HS256');

  /// HMAC using SHA-384 hash algorithm
  static const HS384 = _HMACAlgorithm('HS384');

  /// HMAC using SHA-512 hash algorithm
  static const HS512 = _HMACAlgorithm('HS512');

  /// RSASSA-PKCS1-v1_5 using SHA-256 hash algorithm
  static const RS256 = _RSAAlgorithm('RS256');

  /// RSASSA-PKCS1-v1_5 using SHA-384 hash algorithm
  static const RS384 = _RSAAlgorithm('RS384');

  /// RSASSA-PKCS1-v1_5 using SHA-512 hash algorithm
  static const RS512 = _RSAAlgorithm('RS512');

  /// ECDSA using P-256 curve and SHA-256 hash algorithm
  static const ES256 = _ECDSAAlgorithm('ES256');

  /// ECDSA using P-384 curve and SHA-384 hash algorithm
  static const ES384 = _ECDSAAlgorithm('ES384');

  /// ECDSA using P-512 curve and SHA-512 hash algorithm
  static const ES512 = _ECDSAAlgorithm('ES512');

  /// EdDSA using Ed25519 curve algorithm
  static const EdDSA = _EdDSAAlgorithm('EdDSA');

  /// Return the `JWTAlgorithm` from his string name
  static JWTAlgorithm fromName(String name) {
    switch (name) {
      case 'HS256':
        return JWTAlgorithm.HS256;
      case 'HS384':
        return JWTAlgorithm.HS384;
      case 'HS512':
        return JWTAlgorithm.HS512;
      case 'RS256':
        return JWTAlgorithm.RS256;
      case 'RS384':
        return JWTAlgorithm.RS384;
      case 'RS512':
        return JWTAlgorithm.RS512;
      case 'ES256':
        return JWTAlgorithm.ES256;
      case 'ES384':
        return JWTAlgorithm.ES384;
      case 'ES512':
        return JWTAlgorithm.ES512;
      case 'EdDSA':
        return JWTAlgorithm.EdDSA;
      default:
        throw JWTInvalidError('unknown algorithm');
    }
  }

  const JWTAlgorithm();

  /// `JWTAlgorithm` name
  String get name;

  /// Create a signature of the `body` with `key`
  ///
  /// return the signature as bytes
  Uint8List sign(JWTKey key, Uint8List body);

  /// Verify the `signature` of `body` with `key`
  ///
  /// return `true` if the signature is correct `false` otherwise
  bool verify(JWTKey key, Uint8List body, Uint8List signature);
}

class _EdDSAAlgorithm extends JWTAlgorithm {
  final String _name;

  const _EdDSAAlgorithm(this._name);

  @override
  String get name => _name;

  @override
  Uint8List sign(JWTKey key, Uint8List body) {
    assert(key is EdDSAPrivateKey, 'key must be a EdDSAPrivateKey');
    final privateKey = key as EdDSAPrivateKey;

    return ed.sign(privateKey.key, body);
  }

  @override
  bool verify(JWTKey key, Uint8List body, Uint8List signature) {
    assert(key is EdDSAPublicKey, 'key must be a EdDSAPublicKey');
    final publicKey = key as EdDSAPublicKey;

    try {
      return ed.verify(publicKey.key, body, signature);
    } catch (ex) {
      return false;
    }
  }
}

class _HMACAlgorithm extends JWTAlgorithm {
  final String _name;

  const _HMACAlgorithm(this._name);

  @override
  String get name => _name;

  @override
  Uint8List sign(JWTKey key, Uint8List body) {
    assert(key is SecretKey, 'key must be a SecretKey');
    final secretKey = key as SecretKey;

    final hmac = Hmac(_getHash(name), utf8.encode(secretKey.key));

    return Uint8List.fromList(hmac.convert(body).bytes);
  }

  @override
  bool verify(JWTKey key, Uint8List body, Uint8List signature) {
    assert(key is SecretKey, 'key must be a SecretKey');

    final actual = sign(key, body);

    if (actual.length != signature.length) return false;

    for (var i = 0; i < actual.length; i++) {
      if (actual[i] != signature[i]) return false;
    }

    return true;
  }

  Hash _getHash(String name) {
    switch (name) {
      case 'HS256':
        return sha256;
      case 'HS384':
        return sha384;
      case 'HS512':
        return sha512;
      default:
        throw ArgumentError.value(name, 'name', 'unknown hash name');
    }
  }
}

class _RSAAlgorithm extends JWTAlgorithm {
  final String _name;

  const _RSAAlgorithm(this._name);

  @override
  String get name => _name;

  @override
  Uint8List sign(JWTKey key, Uint8List body) {
    assert(key is RSAPrivateKey, 'key must be a RSAPrivateKey');
    final privateKey = key as RSAPrivateKey;

    final signer = pc.Signer('${_getHash(name)}/RSA');
    final params = pc.PrivateKeyParameter<pc.RSAPrivateKey>(privateKey.key);

    signer.init(true, params);

    final signature = signer.generateSignature(
      Uint8List.fromList(body),
    ) as pc.RSASignature;

    return signature.bytes;
  }

  @override
  bool verify(JWTKey key, Uint8List body, Uint8List signature) {
    assert(key is RSAPublicKey, 'key must be a RSAPublicKey');
    final publicKey = key as RSAPublicKey;

    try {
      final signer = pc.Signer('${_getHash(name)}/RSA');
      final params = pc.PublicKeyParameter<pc.RSAPublicKey>(publicKey.key);

      signer.init(false, params);

      final msg = Uint8List.fromList(body);
      final sign = pc.RSASignature(Uint8List.fromList(signature));

      return signer.verifySignature(msg, sign);
    } catch (ex) {
      return false;
    }
  }

  String _getHash(String name) {
    switch (name) {
      case 'RS256':
        return 'SHA-256';
      case 'RS384':
        return 'SHA-384';
      case 'RS512':
        return 'SHA-512';
      default:
        throw ArgumentError.value(name, 'name', 'unknown hash name');
    }
  }
}

class _ECDSAAlgorithm extends JWTAlgorithm {
  final String _name;

  const _ECDSAAlgorithm(this._name);

  @override
  String get name => _name;

  @override
  Uint8List sign(JWTKey key, Uint8List body) {
    assert(key is ECPrivateKey, 'key must be a ECPublicKey');
    final privateKey = key as ECPrivateKey;

    final signer = pc.Signer('${_getHash(name)}/DET-ECDSA');
    final params = pc.PrivateKeyParameter<pc.ECPrivateKey>(privateKey.key);

    signer.init(true, params);

    final signature = signer.generateSignature(
      Uint8List.fromList(body),
    ) as pc.ECSignature;

    final len = privateKey.size;
    final bytes = Uint8List(len * 2);
    bytes.setRange(0, len, bigIntToBytes(signature.r).toList().reversed);
    bytes.setRange(len, len * 2, bigIntToBytes(signature.s).toList().reversed);

    return bytes;
  }

  @override
  bool verify(JWTKey key, Uint8List body, Uint8List signature) {
    assert(key is ECPublicKey, 'key must be a ECPublicKey');
    final publicKey = key as ECPublicKey;

    final signer = pc.Signer('${_getHash(name)}/DET-ECDSA');
    final params = pc.PublicKeyParameter<pc.ECPublicKey>(publicKey.key);

    signer.init(false, params);

    final len = signature.length ~/ 2;
    final sign = pc.ECSignature(
      bigIntFromBytes(signature.sublist(0, len)),
      bigIntFromBytes(signature.sublist(len)),
    );

    return signer.verifySignature(body, sign);
  }

  String _getHash(String name) {
    switch (name) {
      case 'ES256':
        return 'SHA-256';
      case 'ES384':
        return 'SHA-384';
      case 'ES512':
        return 'SHA-512';
      default:
        throw ArgumentError.value(name, 'name', 'unknown hash name');
    }
  }
}
