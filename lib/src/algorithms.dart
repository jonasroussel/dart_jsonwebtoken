import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:pointycastle/pointycastle.dart' hide PrivateKey, PublicKey;
import 'package:rsa_pkcs/rsa_pkcs.dart' hide RSAPrivateKey, RSAPublicKey;

abstract class JWTAlgorithm {
  static const HS256 = HS256Algorithm();
  static const RS256 = RS256Algorithm();

  static JWTAlgorithm fromName(String name) {
    switch (name) {
      case 'HS256':
        return JWTAlgorithm.HS256;
      case 'RS256':
        return JWTAlgorithm.RS256;
      default:
        throw JWTInvalidError('unknown algorithm');
    }
  }

  const JWTAlgorithm();

  String get name;
  List<int> sign(Key key, List<int> body);
  bool verify(Key key, List<int> body, List<int> signature);
}

class HS256Algorithm extends JWTAlgorithm {
  const HS256Algorithm();

  @override
  String get name => 'HS256';

  @override
  List<int> sign(Key key, List<int> body) {
    assert(key is SecretKey, 'key must be a SecretKey');
    final secretKey = key as SecretKey;

    final hmac = Hmac(sha256, utf8.encode(secretKey.key));
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
}

class RS256Algorithm extends JWTAlgorithm {
  const RS256Algorithm();

  @override
  String get name => 'RS256';

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

    final signer = Signer('SHA-256/RSA');
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
      final signer = Signer('SHA-256/RSA');
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

      return signer.verifySignature(Uint8List.fromList(body), RSASignature(Uint8List.fromList(signature)));
    } catch (ex) {
      return false;
    }
  }
}
