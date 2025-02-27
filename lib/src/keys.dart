import 'dart:convert';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:pointycastle/pointycastle.dart' as pc;

import 'algorithms.dart';
import 'exceptions.dart';
import 'helpers.dart';
import 'key_parser.dart';

abstract class JWTKey {
  Map<String, dynamic> toJWK({String? keyID});
}

/// For HMAC algorithms
class SecretKey extends JWTKey {
  String key;
  bool isBase64Encoded;

  SecretKey(this.key, {this.isBase64Encoded = false});

  @override
  Map<String, dynamic> toJWK({String? keyID, HMACAlgorithm? algorithm}) {
    final keyBytes = decodeHMACSecret(key, isBase64Encoded);

    Map<String, dynamic> jwk = {
      'kty': 'oct',
      'use': 'sig',
      'k': base64Unpadded(base64Url.encode(keyBytes)),
    };

    if (keyID != null) jwk['kid'] = keyID;
    if (algorithm != null) jwk['alg'] = algorithm.name;

    return jwk;
  }
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

  @override
  Map<String, dynamic> toJWK({String? keyID, RSAAlgorithm? algorithm}) {
    final p = key.p;
    if (p == null) throw ArgumentError('p is null');
    final q = key.q;
    if (q == null) throw ArgumentError('q is null');
    final n = key.n;
    if (n == null) throw ArgumentError('n is null');
    final e = key.publicExponent;
    if (e == null) throw ArgumentError('e is null');
    final d = key.privateExponent;
    if (d == null) throw ArgumentError('d is null');
    final dp = d % (p - BigInt.one);
    final dq = d % (q - BigInt.one);
    final qi = q.modInverse(p);

    Map<String, dynamic> jwk = {
      'kty': 'RSA',
      'use': 'sig',
      'p': base64Unpadded(base64Url.encode(bigIntToBytes(p).reversed.toList())),
      'q': base64Unpadded(base64Url.encode(bigIntToBytes(q).reversed.toList())),
      'd': base64Unpadded(base64Url.encode(bigIntToBytes(d).reversed.toList())),
      'e': base64Unpadded(base64Url.encode(bigIntToBytes(e).reversed.toList())),
      'dp':
          base64Unpadded(base64Url.encode(bigIntToBytes(dp).reversed.toList())),
      'dq':
          base64Unpadded(base64Url.encode(bigIntToBytes(dq).reversed.toList())),
      'qi':
          base64Unpadded(base64Url.encode(bigIntToBytes(qi).reversed.toList())),
      'n': base64Unpadded(base64Url.encode(bigIntToBytes(n).reversed.toList())),
    };

    if (keyID != null) jwk['kid'] = keyID;
    if (algorithm != null) jwk['alg'] = algorithm.name;

    return jwk;
  }
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

  @override
  Map<String, dynamic> toJWK({String? keyID, RSAAlgorithm? algorithm}) {
    final e = key.publicExponent;
    if (e == null) throw ArgumentError('e is null');
    final n = key.modulus;
    if (n == null) throw ArgumentError('n is null');

    Map<String, dynamic> jwk = {
      'kty': 'RSA',
      'use': 'sig',
      'e': base64Unpadded(base64Url.encode(bigIntToBytes(e).reversed.toList())),
      'n': base64Unpadded(base64Url.encode(bigIntToBytes(n).reversed.toList())),
    };

    if (keyID != null) jwk['kid'] = keyID;
    if (algorithm != null) jwk['alg'] = algorithm.name;

    return jwk;
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

  @override
  Map<String, dynamic> toJWK({String? keyID, ECDSAAlgorithm? algorithm}) {
    final params = key.parameters;
    if (params == null) throw ArgumentError('parameters is null');
    final curve = curveOpenSSLToNIST(params.domainName);
    final d = key.d;
    if (d == null) throw ArgumentError('d is null');
    final Q = params.G * d;
    if (Q == null) throw ArgumentError('Q is null');
    final x = Q.x?.toBigInteger();
    if (x == null) throw ArgumentError('x is null');
    final y = Q.y?.toBigInteger();
    if (y == null) throw ArgumentError('y is null');

    Map<String, dynamic> jwk = {
      'kty': 'EC',
      'use': 'sig',
      'crv': curve,
      'd': base64Unpadded(base64Url.encode(bigIntToBytes(d).reversed.toList())),
      'x': base64Unpadded(base64Url.encode(bigIntToBytes(x).reversed.toList())),
      'y': base64Unpadded(base64Url.encode(bigIntToBytes(y).reversed.toList())),
    };

    if (keyID != null) jwk['kid'] = keyID;
    final alg = algorithm?.name ?? ecCurveToAlgorithm(curve)?.name;
    if (alg != null) jwk['alg'] = alg;

    return jwk;
  }
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

  @override
  Map<String, dynamic> toJWK({String? keyID, ECDSAAlgorithm? algorithm}) {
    final params = key.parameters;
    if (params == null) throw ArgumentError('parameters is null');
    final curve = curveOpenSSLToNIST(params.domainName);
    final x = key.Q?.x?.toBigInteger();
    if (x == null) throw ArgumentError('x is null');
    final y = key.Q?.y?.toBigInteger();
    if (y == null) throw ArgumentError('y is null');

    Map<String, dynamic> jwk = {
      'kty': 'EC',
      'use': 'sig',
      'crv': curve,
      'x': base64Unpadded(base64Url.encode(bigIntToBytes(x).reversed.toList())),
      'y': base64Unpadded(base64Url.encode(bigIntToBytes(y).reversed.toList())),
    };

    if (keyID != null) jwk['kid'] = keyID;
    final alg = algorithm?.name ?? ecCurveToAlgorithm(curve)?.name;
    if (alg != null) jwk['alg'] = alg;

    return jwk;
  }
}

/// For EdDSA algorithm, in sign method
class EdDSAPrivateKey extends JWTKey {
  ed.PrivateKey key;

  EdDSAPrivateKey(List<int> bytes) : key = ed.PrivateKey(bytes);

  EdDSAPrivateKey.fromPEM(String pem)
      : key = KeyParser.edPrivateKeyFromPEM(pem);

  @override
  Map<String, dynamic> toJWK({String? keyID}) {
    Map<String, dynamic> jwk = {
      'kty': 'OKP',
      'use': 'sig',
      'crv': 'Ed25519',
      'd': base64Unpadded(base64Url.encode(key.bytes.sublist(0, 32))),
      'x': base64Unpadded(base64Url.encode(key.bytes.sublist(32))),
      'alg': 'EdDSA',
    };

    if (keyID != null) jwk['kid'] = keyID;

    return jwk;
  }
}

/// For EdDSA algorithm, in verify method
class EdDSAPublicKey extends JWTKey {
  ed.PublicKey key;

  EdDSAPublicKey(List<int> bytes) : key = ed.PublicKey(bytes);

  EdDSAPublicKey.fromPEM(String pem) : key = KeyParser.edPublicKeyFromPEM(pem);

  @override
  Map<String, dynamic> toJWK({String? keyID}) {
    Map<String, dynamic> jwk = {
      'kty': 'OKP',
      'use': 'sig',
      'crv': 'Ed25519',
      'x': base64Unpadded(base64Url.encode(key.bytes)),
      'alg': 'EdDSA',
    };

    if (keyID != null) jwk['kid'] = keyID;

    return jwk;
  }
}
