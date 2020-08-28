import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:pointycastle/pointycastle.dart' hide PrivateKey, PublicKey;
import 'package:rsa_pkcs/rsa_pkcs.dart' hide RSAPrivateKey, RSAPublicKey;

abstract class JWTAlgorithm {
  static const HS256 = HMACAlgorithm('HS256');
  static const HS384 = HMACAlgorithm('HS384');
  static const HS512 = HMACAlgorithm('HS512');
  static const RS256 = RSAAlgorithm('RS256');
  static const RS384 = RSAAlgorithm('RS384');
  static const RS512 = RSAAlgorithm('RS512');

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
      default:
        throw JWTInvalidError('unknown algorithm');
    }
  }

  const JWTAlgorithm();

  String get name;
  List<int> sign(Key key, List<int> body);
  bool verify(Key key, List<int> body, List<int> signature);
}

class HMACAlgorithm extends JWTAlgorithm {
  final String _name;

  const HMACAlgorithm(this._name);

  @override
  String get name => _name;

  @override
  List<int> sign(Key key, List<int> body) {
    assert(key is SecretKey, 'key must be a SecretKey');
    final secretKey = key as SecretKey;

    final hmac = Hmac(_getHash(name), utf8.encode(secretKey.key));
    return hmac.convert(body).bytes;
  }

  @override
  bool verify(Key key, List<int> body, List<int> signature) {
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

  const RSAAlgorithm(this._name);

  @override
  String get name => _name;

  @override
  List<int> sign(Key key, List<int> body) {
    assert(key is PrivateKey, 'key must be a PrivateKey');
    final privateKey = key as PrivateKey;

    final parser = RSAPKCSParser();
    RSAKeyPair pair;

    pair = parser.parsePEM(privateKey.key, password: privateKey.passphrase);
    if (pair.private == null) {
      throw JWTInvalidError('invalid private RSA key');
    }

    final signer = Signer('${_getHash(name)}/RSA');
    final params = ParametersWithRandom(
      PrivateKeyParameter<RSAPrivateKey>(
        RSAPrivateKey(
          pair.private.modulus,
          pair.private.privateExponent,
          pair.private.prime1,
          pair.private.prime2,
        ),
      ),
      SecureRandom('AES/CTR/PRNG'),
    );

    signer.init(true, params);

    RSASignature signature = signer.generateSignature(Uint8List.fromList(body));

    return signature.bytes.toList(growable: false);
  }

  @override
  bool verify(Key key, List<int> body, List<int> signature) {
    assert(key is PublicKey, 'key must be a PublicKey');
    final publicKey = key as PublicKey;

    final parser = RSAPKCSParser();
    RSAKeyPair pair;

    try {
      pair = parser.parsePEM(publicKey.key, password: publicKey.passphrase);
      assert(pair.public != null);
    } catch (ex) {
      throw JWTInvalidError('invalid public RSA key');
    }

    try {
      final signer = Signer('${_getHash(name)}/RSA');
      final params = ParametersWithRandom(
        PublicKeyParameter<RSAPublicKey>(
          RSAPublicKey(
            pair.public.modulus,
            BigInt.from(pair.public.publicExponent),
          ),
        ),
        SecureRandom('AES/CTR/PRNG'),
      );

      signer.init(false, params);

      final msg = Uint8List.fromList(body);
      final sign = RSASignature(Uint8List.fromList(signature));

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
