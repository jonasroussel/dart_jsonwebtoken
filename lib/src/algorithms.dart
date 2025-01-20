import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:pointycastle/pointycastle.dart' as pc;

import 'exceptions.dart';
import 'keys.dart';
import 'helpers.dart';

abstract class JWTAlgorithm {
  /// HMAC using SHA-256 hash algorithm
  static const HS256 = HMACAlgorithm('HS256');

  /// HMAC using SHA-384 hash algorithm
  static const HS384 = HMACAlgorithm('HS384');

  /// HMAC using SHA-512 hash algorithm
  static const HS512 = HMACAlgorithm('HS512');

  /// RSASSA-PSS using SHA-256 hash algorithm
  static const PS256 = RSAAlgorithm('PS256', null);

  /// RSASSA-PSS using SHA-384 hash algorithm
  static const PS384 = RSAAlgorithm('PS384', null);

  /// RSASSA-PSS using SHA-512 hash algorithm
  static const PS512 = RSAAlgorithm('PS512', null);

  /// RSASSA-PKCS1-v1_5 using SHA-256 hash algorithm
  static const RS256 = RSAAlgorithm('RS256', null);

  /// RSASSA-PKCS1-v1_5 using SHA-384 hash algorithm
  static const RS384 = RSAAlgorithm('RS384', null);

  /// RSASSA-PKCS1-v1_5 using SHA-512 hash algorithm
  static const RS512 = RSAAlgorithm('RS512', null);

  /// ECDSA using P-256 curve and SHA-256 hash algorithm
  static const ES256 = ECDSAAlgorithm('ES256');

  /// ECDSA using P-384 curve and SHA-384 hash algorithm
  static const ES384 = ECDSAAlgorithm('ES384');

  /// ECDSA using P-512 curve and SHA-512 hash algorithm
  static const ES512 = ECDSAAlgorithm('ES512');

  /// ECDSA using secp256k1 curve and SHA-256 hash algorithm
  static const ES256K = ECDSAAlgorithm('ES256K');

  /// EdDSA using Ed25519 curve algorithm
  static const EdDSA = EdDSAAlgorithm('EdDSA');

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
      case 'ES256K':
        return JWTAlgorithm.ES256K;
      case 'EdDSA':
        return JWTAlgorithm.EdDSA;
      case 'PS256':
        return JWTAlgorithm.PS256;
      case 'PS384':
        return JWTAlgorithm.PS384;
      case 'PS512':
        return JWTAlgorithm.PS512;
      default:
        throw JWTInvalidException('unknown algorithm');
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

class EdDSAAlgorithm extends JWTAlgorithm {
  final String _name;

  const EdDSAAlgorithm(this._name);

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

class HMACAlgorithm extends JWTAlgorithm {
  final String _name;

  const HMACAlgorithm(this._name);

  @override
  String get name => _name;

  @override
  Uint8List sign(JWTKey key, Uint8List body) {
    assert(key is SecretKey, 'key must be a SecretKey');
    final secretKey = key as SecretKey;

    final hmac = Hmac(
      _getHash(name),
      secretKey.isBase64Encoded
          ? base64Decode(secretKey.key)
          : utf8.encode(secretKey.key),
    );

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

class RSAAlgorithm extends JWTAlgorithm {
  final String _name;
  final Random? _random;

  const RSAAlgorithm(this._name, this._random);

  @override
  String get name => _name;

  @override
  Uint8List sign(JWTKey key, Uint8List body) {
    assert(key is RSAPrivateKey, 'key must be a RSAPrivateKey');
    final privateKey = key as RSAPrivateKey;

    final algorithm = _getAlgorithm(name);

    final signer = pc.Signer('${_getHash(name)}/${algorithm}');
    pc.CipherParameters params = pc.PrivateKeyParameter<pc.RSAPrivateKey>(
      privateKey.key,
    );

    if (algorithm == 'PSS') {
      final random = _random ?? Random.secure();
      final salt = Uint8List.fromList(
        List.generate(_getSaltLength(name), (_) => random.nextInt(256)),
      );

      params = pc.ParametersWithSalt(
        params,
        salt,
      );
    }

    signer.init(true, params);

    final signature = signer.generateSignature(Uint8List.fromList(body));

    if (signature is pc.PSSSignature) {
      return signature.bytes;
    } else {
      return (signature as pc.RSASignature).bytes;
    }
  }

  @override
  bool verify(JWTKey key, Uint8List body, Uint8List signature) {
    assert(key is RSAPublicKey, 'key must be a RSAPublicKey');
    final publicKey = key as RSAPublicKey;

    try {
      final algorithm = _getAlgorithm(name);

      final signer = pc.Signer('${_getHash(name)}/${algorithm}');
      pc.CipherParameters params = pc.PublicKeyParameter<pc.RSAPublicKey>(
        publicKey.key,
      );

      if (algorithm == 'PSS') {
        params = pc.ParametersWithSaltConfiguration(
          params,
          pc.SecureRandom('Fortuna'),
          _getSaltLength(name),
        );
      }

      signer.init(false, params);

      final msg = Uint8List.fromList(body);
      final sign = algorithm == 'PSS'
          ? pc.PSSSignature(Uint8List.fromList(signature))
          : pc.RSASignature(Uint8List.fromList(signature));

      return signer.verifySignature(msg, sign);
    } catch (ex) {
      print(ex);
      return false;
    }
  }

  String _getHash(String name) {
    switch (name) {
      case 'RS256':
      case 'PS256':
        return 'SHA-256';
      case 'RS384':
      case 'PS384':
        return 'SHA-384';
      case 'RS512':
      case 'PS512':
        return 'SHA-512';
      default:
        throw ArgumentError.value(name, 'name', 'unknown hash name');
    }
  }

  String _getAlgorithm(String name) {
    switch (name) {
      case 'RS256':
      case 'RS384':
      case 'RS512':
        return 'RSA';
      case 'PS256':
      case 'PS384':
      case 'PS512':
        return 'PSS';
      default:
        throw ArgumentError.value(name, 'name', 'unknown algorithm name');
    }
  }

  int _getSaltLength(String name) {
    switch (name) {
      case 'PS256':
        return 32;
      case 'PS384':
        return 48;
      case 'PS512':
        return 64;
      default:
        return 32;
    }
  }
}

class ECDSAAlgorithm extends JWTAlgorithm {
  final String _name;

  const ECDSAAlgorithm(this._name);

  @override
  String get name => _name;

  @override
  Uint8List sign(JWTKey key, Uint8List body) {
    assert(key is ECPrivateKey, 'key must be a ECPrivateKey');
    final privateKey = key as ECPrivateKey;

    final signer = pc.Signer('${_getHash(name)}/DET-ECDSA');
    final params = pc.PrivateKeyParameter<pc.ECPrivateKey>(privateKey.key);

    signer.init(true, params);

    final signature = signer.generateSignature(
      Uint8List.fromList(body),
    ) as pc.ECSignature;

    final rBytes = bigIntToBytes(signature.r).toList();
    while (rBytes.length < 32) {
      rBytes.add(0);
    }

    final sBytes = bigIntToBytes(signature.s).toList();
    while (sBytes.length < 32) {
      sBytes.add(0);
    }

    final len = privateKey.size;
    final bytes = Uint8List(len * 2);

    bytes.setRange(len - rBytes.length, len, rBytes.reversed);
    bytes.setRange((len * 2) - sBytes.length, len * 2, sBytes.reversed);

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
      case 'ES256K':
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
