import 'dart:convert';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:pointycastle/ecc/ecc_fp.dart' as ecc_fp;
import 'package:pointycastle/pointycastle.dart' as pc;

import 'algorithms.dart';
import 'exceptions.dart';
import 'helpers.dart';
import 'key_parser.dart';

abstract class JWTKey {
  /// Convert the key to a JWK JSON object representation
  Map<String, dynamic> toJWK({String? keyID});

  /// Parse a JWK JSON object into any valid JWTKey,
  ///
  /// Including `SecretKey`, `RSAPrivateKey`, `RSAPublicKey`, `ECPrivateKey`,
  /// `ECPublicKey`, `EdDSAPrivateKey` and `EdDSAPublicKey`.
  ///
  /// Throws a `JWTParseException` if the JWK is invalid or unsupported.
  static JWTKey fromJWK(Map<String, dynamic> jwk) => switch (jwk) {
    {'kty': 'oct', 'k': final String k} => SecretKey(
      base64Padded(k),
      isBase64Encoded: true,
    ),
    {
      'kty': 'RSA',
      'p': final String p,
      'q': final String q,
      'd': final String d,
      'n': final String n,
    } =>
      RSAPrivateKey.raw(
        pc.RSAPrivateKey(
          bigIntFromBytes(base64Url.decode(base64Padded(n))),
          bigIntFromBytes(base64Url.decode(base64Padded(d))),
          bigIntFromBytes(base64Url.decode(base64Padded(p))),
          bigIntFromBytes(base64Url.decode(base64Padded(q))),
        ),
      ),
    {'kty': 'RSA', 'e': final String e, 'n': final String n} =>
      RSAPublicKey.raw(
        pc.RSAPublicKey(
          bigIntFromBytes(base64Url.decode(base64Padded(n))),
          bigIntFromBytes(base64Url.decode(base64Padded(e))),
        ),
      ),
    {'kty': 'EC', 'crv': final String crv, 'd': final String d}
        when ['P-256', 'P-384', 'P-521', 'secp256k1'].contains(crv) =>
      ECPrivateKey.raw(
        pc.ECPrivateKey(
          bigIntFromBytes(base64Url.decode(base64Padded(d))),
          pc.ECDomainParameters(curveNISTToOpenSSL(crv)),
        ),
      ),
    {
      'kty': 'EC',
      'crv': final String crv,
      'x': final String x,
      'y': final String y,
    }
        when ['P-256', 'P-384', 'P-521', 'secp256k1'].contains(crv) =>
      ECPublicKey.raw(() {
        final params = pc.ECDomainParameters(curveNISTToOpenSSL(crv));
        return pc.ECPublicKey(
          ecc_fp.ECPoint(
            params.curve as ecc_fp.ECCurve,
            params.curve.fromBigInteger(
                  bigIntFromBytes(base64Url.decode(base64Padded(x))),
                )
                as ecc_fp.ECFieldElement?,
            params.curve.fromBigInteger(
                  bigIntFromBytes(base64Url.decode(base64Padded(y))),
                )
                as ecc_fp.ECFieldElement?,
          ),
          params,
        );
      }()),
    {
      'kty': 'OKP',
      'crv': 'Ed25519',
      'd': final String d,
      'x': final String x,
    } =>
      EdDSAPrivateKey(() {
        final dBytes = base64Url.decode(base64Padded(d));
        final xBytes = base64Url.decode(base64Padded(x));
        return Uint8List(dBytes.length + xBytes.length)
          ..setAll(0, dBytes)
          ..setAll(dBytes.length, xBytes);
      }()),
    {'kty': 'OKP', 'crv': 'Ed25519', 'x': final String x} => EdDSAPublicKey(
      base64Url.decode(base64Padded(x)),
    ),
    {'kty': 'EC', 'crv': final String _} => throw JWTParseException(
      'Unsupported curve',
    ),
    _ => throw JWTParseException('Invalid or unsupported JWK'),
  };
}

/// For HMAC algorithms
class SecretKey extends JWTKey {
  String key;
  bool isBase64Encoded;

  SecretKey(this.key, {this.isBase64Encoded = false});

  @override
  Map<String, dynamic> toJWK({String? keyID, HMACAlgorithm? algorithm}) {
    final keyBytes = decodeHMACSecret(key, isBase64Encoded);

    final jwk = <String, dynamic>{
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

  RSAPrivateKey.raw(this.key);
  RSAPrivateKey.clone(RSAPrivateKey other) : key = other.key;
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

    final jwk = <String, dynamic>{
      'kty': 'RSA',
      'use': 'sig',
      'p': base64Unpadded(base64Url.encode(bigIntToBytes(p).reversed.toList())),
      'q': base64Unpadded(base64Url.encode(bigIntToBytes(q).reversed.toList())),
      'd': base64Unpadded(base64Url.encode(bigIntToBytes(d).reversed.toList())),
      'e': base64Unpadded(base64Url.encode(bigIntToBytes(e).reversed.toList())),
      'dp': base64Unpadded(
        base64Url.encode(bigIntToBytes(dp).reversed.toList()),
      ),
      'dq': base64Unpadded(
        base64Url.encode(bigIntToBytes(dq).reversed.toList()),
      ),
      'qi': base64Unpadded(
        base64Url.encode(bigIntToBytes(qi).reversed.toList()),
      ),
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

  RSAPublicKey.raw(this.key);
  RSAPublicKey.clone(RSAPublicKey other) : key = other.key;
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

    final jwk = <String, dynamic>{
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
    final parsedKey = KeyParser.ecPrivateKeyFromPEM(
      pem,
      pkcs1: pem.startsWith(KeyParser.BEGIN_EC_PRIVATE_KEY),
    );
    final params = parsedKey.parameters;

    if (params == null) {
      throw JWTParseException('ECPrivateKey parameters are invalid');
    }

    key = parsedKey;
    size = (params.curve.fieldSize / 8).ceil();
  }

  ECPrivateKey.raw(pc.ECPrivateKey other) {
    final params = other.parameters;

    if (params == null) {
      throw JWTParseException('ECPrivateKey parameters are invalid');
    }

    key = other;
    size = (params.curve.fieldSize / 8).ceil();
  }
  ECPrivateKey.clone(ECPrivateKey other) : key = other.key, size = other.size;
  ECPrivateKey.bytes(Uint8List bytes) {
    key = KeyParser.ecPrivateKey(bytes);

    final params = key.parameters;
    if (params == null) {
      throw JWTParseException('ECPrivateKey parameters are invalid');
    }

    size = (params.curve.fieldSize / 8).ceil();
  }

  @override
  Map<String, dynamic> toJWK({String? keyID, ECDSAAlgorithm? algorithm}) {
    final params = key.parameters;
    if (params == null) throw ArgumentError('parameters is null');
    final curve = curveOpenSSLToNIST(params.domainName);
    final d = key.d;
    if (d == null) throw ArgumentError('d is null');
    final qPoint = params.G * d;
    if (qPoint == null) throw ArgumentError('Q is null');
    final x = qPoint.x?.toBigInteger();
    if (x == null) throw ArgumentError('x is null');
    final y = qPoint.y?.toBigInteger();
    if (y == null) throw ArgumentError('y is null');

    final jwk = <String, dynamic>{
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

  ECPublicKey.raw(this.key);
  ECPublicKey.clone(ECPublicKey other) : key = other.key;
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

    final jwk = <String, dynamic>{
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
    final jwk = <String, dynamic>{
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
    final jwk = <String, dynamic>{
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
