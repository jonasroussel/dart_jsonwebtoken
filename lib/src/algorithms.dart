// ignore_for_file: constant_identifier_names
import 'dart:math';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:pointycastle/pointycastle.dart' as pc;

import 'exceptions.dart';
import 'helpers.dart';
import 'keys.dart';

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

  /// ECDSA using P-521 curve and SHA-512 hash algorithm
  static const ES512 = ECDSAAlgorithm('ES512');

  /// ECDSA using secp256k1 curve and SHA-256 hash algorithm
  static const ES256K = ECDSAAlgorithm('ES256K');

  /// EdDSA using Ed25519 curve algorithm
  static const EdDSA = EdDSAAlgorithm('EdDSA');

  /// Return the `JWTAlgorithm` from his string name
  static JWTAlgorithm fromName(String name) => switch (name) {
    'HS256' => JWTAlgorithm.HS256,
    'HS384' => JWTAlgorithm.HS384,
    'HS512' => JWTAlgorithm.HS512,
    'RS256' => JWTAlgorithm.RS256,
    'RS384' => JWTAlgorithm.RS384,
    'RS512' => JWTAlgorithm.RS512,
    'ES256' => JWTAlgorithm.ES256,
    'ES384' => JWTAlgorithm.ES384,
    'ES512' => JWTAlgorithm.ES512,
    'ES256K' => JWTAlgorithm.ES256K,
    'EdDSA' => JWTAlgorithm.EdDSA,
    'PS256' => JWTAlgorithm.PS256,
    'PS384' => JWTAlgorithm.PS384,
    'PS512' => JWTAlgorithm.PS512,
    _ => throw JWTInvalidException('unknown algorithm'),
  };

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

    final keyBytes = decodeHMACSecret(secretKey.key, secretKey.isBase64Encoded);

    final hmac = pc.Mac('${_getHash(name)}/HMAC')
      ..init(pc.KeyParameter(keyBytes));

    return Uint8List.fromList(hmac.process(body));
  }

  @override
  bool verify(JWTKey key, Uint8List body, Uint8List signature) {
    assert(key is SecretKey, 'key must be a SecretKey');

    final actual = sign(key, body);

    return fixedTimeBytesEquals(actual, signature);
  }

  String _getHash(String name) => switch (name) {
    'HS256' => 'SHA-256',
    'HS384' => 'SHA-384',
    'HS512' => 'SHA-512',
    _ => throw ArgumentError.value(name, 'name', 'unknown hash name'),
  };
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
    final signer = pc.Signer('${_getHash(name)}/$algorithm');
    final params = pc.PrivateKeyParameter<pc.RSAPrivateKey>(privateKey.key);

    if (algorithm == 'PSS') {
      final random = _random ?? Random.secure();
      final salt = Uint8List.fromList(
        List.generate(_getSaltLength(name), (_) => random.nextInt(256)),
      );

      signer.init(true, pc.ParametersWithSalt(params, salt));
    } else {
      signer.init(true, params);
    }

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
      final signer = pc.Signer('${_getHash(name)}/$algorithm');
      final params = pc.PublicKeyParameter<pc.RSAPublicKey>(publicKey.key);

      if (algorithm == 'PSS') {
        signer.init(
          false,
          pc.ParametersWithSaltConfiguration(
            params,
            pc.SecureRandom('Fortuna'),
            _getSaltLength(name),
          ),
        );
      } else {
        signer.init(false, params);
      }

      final msg = Uint8List.fromList(body);
      final sign = algorithm == 'PSS'
          ? pc.PSSSignature(Uint8List.fromList(signature))
          : pc.RSASignature(Uint8List.fromList(signature));

      return signer.verifySignature(msg, sign);
    } catch (ex) {
      return false;
    }
  }

  String _getHash(String name) => switch (name) {
    'RS256' || 'PS256' => 'SHA-256',
    'RS384' || 'PS384' => 'SHA-384',
    'RS512' || 'PS512' => 'SHA-512',
    _ => throw ArgumentError.value(name, 'name', 'unknown hash name'),
  };

  String _getAlgorithm(String name) => switch (name) {
    'RS256' || 'RS384' || 'RS512' => 'RSA',
    'PS256' || 'PS384' || 'PS512' => 'PSS',
    _ => throw ArgumentError.value(name, 'name', 'unknown algorithm name'),
  };

  int _getSaltLength(String name) => switch (name) {
    'PS256' => 32,
    'PS384' => 48,
    'PS512' => 64,
    _ => 32,
  };
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

    final signer = pc.Signer('${_getHash(name)}/DET-ECDSA')
      ..init(true, pc.PrivateKeyParameter<pc.ECPrivateKey>(privateKey.key));

    final signature =
        signer.generateSignature(Uint8List.fromList(body)) as pc.ECSignature;

    final rBytes = bigIntToBytes(signature.r).toList();
    while (rBytes.length < 32) {
      rBytes.add(0);
    }

    final sBytes = bigIntToBytes(signature.s).toList();
    while (sBytes.length < 32) {
      sBytes.add(0);
    }

    final len = privateKey.size;
    final bytes = Uint8List(len * 2)
      ..setRange(len - rBytes.length, len, rBytes.reversed)
      ..setRange((len * 2) - sBytes.length, len * 2, sBytes.reversed);

    return bytes;
  }

  @override
  bool verify(JWTKey key, Uint8List body, Uint8List signature) {
    assert(key is ECPublicKey, 'key must be a ECPublicKey');
    final publicKey = key as ECPublicKey;

    final signer = pc.Signer('${_getHash(name)}/DET-ECDSA')
      ..init(false, pc.PublicKeyParameter<pc.ECPublicKey>(publicKey.key));

    final len = signature.length ~/ 2;
    final sign = pc.ECSignature(
      bigIntFromBytes(signature.sublist(0, len)),
      bigIntFromBytes(signature.sublist(len)),
    );

    return signer.verifySignature(body, sign);
  }

  String _getHash(String name) => switch (name) {
    'ES256' || 'ES256K' => 'SHA-256',
    'ES384' => 'SHA-384',
    'ES512' => 'SHA-512',
    _ => throw ArgumentError.value(name, 'name', 'unknown hash name'),
  };
}
