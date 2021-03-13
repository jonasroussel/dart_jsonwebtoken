import 'dart:typed_data';
import 'dart:convert';

import 'package:pointycastle/pointycastle.dart'
    hide ECPoint, ECCurve, ECFieldElement;
import 'package:pointycastle/ecc/ecc_fp.dart';

import 'utils.dart';

// RSA Private Key -> PKCS#1 format
const String _pkcs1RSAPrivateHeader = '-----BEGIN RSA PRIVATE KEY-----';
const String _pkcs1RSAPrivateFooter = '-----END RSA PRIVATE KEY-----';

// RSA Private Key -> PKCS#8 format
const String _pkcs8RSAPrivateHeader = '-----BEGIN PRIVATE KEY-----';
const String _pkcs8RSAPrivateFooter = '-----END PRIVATE KEY-----';

// RSA Public Key -> PKCS#1 format
const String _pkcs1RSAPublicHeader = '-----BEGIN RSA PUBLIC KEY-----';
const String _pkcs1RSAPublicFooter = '-----END RSA PUBLIC KEY-----';

// RSA Public Key -> PKCS#1 format
const String _pkcs8RSAPublicHeader = '-----BEGIN PUBLIC KEY-----';
const String _pkcs8RSAPublicFooter = '-----END PUBLIC KEY-----';

// ECDSA Private Key -> SEC 1 format
const String _sec1ECPrivateHeader = '-----BEGIN EC PRIVATE KEY-----';
const String _sec1ECPrivateFooter = '-----END EC PRIVATE KEY-----';

// ECDSA Private Key -> PKCS#8 format
const String _pkcs8ECPrivateHeader = '-----BEGIN PRIVATE KEY-----';
const String _pkcs8ECPrivateFooter = '-----END PRIVATE KEY-----';

// ECDSA Public Key -> PKCS#8 format
const String _pkcs8ECPublicHeader = '-----BEGIN PUBLIC KEY-----';
const String _pkcs8ECPublicFooter = '-----END PUBLIC KEY-----';

// ECDSA Curves OID to DomainName
const Map<String, String> _ecCurves = {
  '1.2.840.10045.3.1.7': 'prime256v1', // P-256
  '1.3.132.0.10': 'secp256k1', // P-256
  '1.3.132.0.34': 'secp384r1', // P-384
  '1.3.132.0.35': 'secp521r1', // P-512
};

/// RSA Private Key -> PKCS#1 parser
RSAPrivateKey _pkcs1RSAPrivateKey(Uint8List bytes) {
  final parser = ASN1Parser(bytes);
  final seq = parser.nextObject() as ASN1Sequence;
  final values = seq.elements.cast<ASN1Integer>();

  return RSAPrivateKey(
    values[1].integer, // modulus
    values[3].integer, // privateExponent
    values[4].integer, // prime1
    values[5].integer, // prime2
  );
}

/// RSA Private Key -> PKCS#8 parser
RSAPrivateKey _pkcs8RSAPrivateKey(Uint8List bytes) {
  final parser = ASN1Parser(bytes);
  final seq = parser.nextObject() as ASN1Sequence;

  final keySeq = seq.elements[2] as ASN1OctetString;
  final keyParser = ASN1Parser(keySeq.octets);

  final valuesSeq = keyParser.nextObject() as ASN1Sequence;
  final values = valuesSeq.elements.cast<ASN1Integer>();

  return RSAPrivateKey(
    values[1].integer, // modulus
    values[3].integer, // privateExponent
    values[4].integer, // prime1
    values[5].integer, // prime2
  );
}

/// RSA Public Key -> PKCS#1 parser
RSAPublicKey _pkcs1RSAPublicKey(Uint8List bytes) {
  final parser = ASN1Parser(bytes);
  final seq = parser.nextObject() as ASN1Sequence;
  final values = seq.elements.cast<ASN1Integer>();

  return RSAPublicKey(
    values[0].integer, // modulus
    values[1].integer, // publicExponent
  );
}

/// RSA Public Key -> PKCS#8 parser
RSAPublicKey _pkcs8RSAPublicKey(Uint8List bytes) {
  final parser = ASN1Parser(bytes);
  final seq = parser.nextObject() as ASN1Sequence;

  final keySeq = seq.elements[1] as ASN1BitString;
  final keyParser = ASN1Parser(keySeq.stringValues as Uint8List);

  final valuesSeq = keyParser.nextObject() as ASN1Sequence;
  final values = valuesSeq.elements.cast<ASN1Integer>();

  return RSAPublicKey(
    values[0].integer, // modulus
    values[1].integer, // publicExponent
  );
}

/// ECDSA Private Key -> SEC 1 parser
ECPrivateKey _sec1ECPrivateKey(Uint8List bytes) {
  final parser = ASN1Parser(bytes);
  final seq = parser.nextObject() as ASN1Sequence;

  final privateKey = seq.elements[1] as ASN1OctetString;

  final params = seq.elements[2];
  final paramsParser = ASN1Parser(params.valueBytes);
  final oid = (paramsParser.nextObject() as ASN1ObjectIdentifier)
      .objectIdentifierAsString;
  final curve = _ecCurves[oid]!;

  return ECPrivateKey(
    decodeBigInt(privateKey.valueBytes),
    ECDomainParameters(curve),
  );
}

/// ECDSA Private Key -> PKCS#8 parser
ECPrivateKey _pkcs8ECPrivateKey(Uint8List bytes) {
  final parser = ASN1Parser(bytes);
  final seq = parser.nextObject() as ASN1Sequence;

  final oidSeq = seq.elements[1] as ASN1Sequence;
  final oid =
      (oidSeq.elements[1] as ASN1ObjectIdentifier).objectIdentifierAsString;
  final curve = _ecCurves[oid]!;

  final privateKeyParser = ASN1Parser(seq.elements[2].valueBytes);
  final privateKeySeq = privateKeyParser.nextObject() as ASN1Sequence;
  final privateKey = (privateKeySeq.elements[1] as ASN1OctetString);

  return ECPrivateKey(
    decodeBigInt(privateKey.valueBytes),
    ECDomainParameters(curve),
  );
}

/// ECDSA Public Key -> PKCS#8 parser
ECPublicKey _pkcs8ECPublicKey(Uint8List bytes) {
  final parser = ASN1Parser(bytes);
  final seq = parser.nextObject() as ASN1Sequence;

  final oidSeq = seq.elements[0] as ASN1Sequence;
  final oid =
      (oidSeq.elements[1] as ASN1ObjectIdentifier).objectIdentifierAsString;
  final curve = _ecCurves[oid]!;

  var publicKeyBytes = seq.elements[1].valueBytes;
  if (publicKeyBytes[0] == 0) {
    publicKeyBytes = publicKeyBytes.sublist(1);
  }

  final compressed = publicKeyBytes[0] != 4;
  final x = publicKeyBytes.sublist(1, (publicKeyBytes.length / 2).round());
  final y = publicKeyBytes.sublist(1 + x.length, publicKeyBytes.length);
  final bigX = decodeBigIntWithSign(1, x);
  final bigY = decodeBigIntWithSign(1, y);
  final params = ECDomainParameters(curve);

  return ECPublicKey(
    ECPoint(
      params.curve as ECCurve,
      params.curve.fromBigInteger(bigX) as ECFieldElement,
      params.curve.fromBigInteger(bigY) as ECFieldElement,
      compressed,
    ),
    params,
  );
}

/// Parse RSA private key from pem string
RSAPrivateKey? parseRSAPrivateKeyPEM(String pem) {
  if (pem.contains(_pkcs1RSAPrivateHeader) &&
      pem.contains(_pkcs1RSAPrivateFooter)) {
    final data = pem
        .substring(
          pem.indexOf(_pkcs1RSAPrivateHeader) + _pkcs1RSAPrivateHeader.length,
          pem.indexOf(_pkcs1RSAPrivateFooter),
        )
        .replaceAll(RegExp(r'[\n\r ]'), '');

    return _pkcs1RSAPrivateKey(base64.decode(data));
  } else if (pem.contains(_pkcs8RSAPrivateHeader) &&
      pem.contains(_pkcs8RSAPrivateFooter)) {
    final data = pem
        .substring(
          pem.indexOf(_pkcs8RSAPrivateHeader) + _pkcs8RSAPrivateHeader.length,
          pem.indexOf(_pkcs8RSAPrivateFooter),
        )
        .replaceAll(RegExp(r'[\n\r ]'), '');

    return _pkcs8RSAPrivateKey(base64.decode(data));
  } else {
    return null;
  }
}

/// Parse RSA public key from pem string
RSAPublicKey? parseRSAPublicKeyPEM(String pem) {
  if (pem.contains(_pkcs1RSAPublicHeader) &&
      pem.contains(_pkcs1RSAPublicFooter)) {
    final data = pem
        .substring(
          pem.indexOf(_pkcs1RSAPublicHeader) + _pkcs1RSAPublicHeader.length,
          pem.indexOf(_pkcs1RSAPublicFooter),
        )
        .replaceAll(RegExp(r'[\n\r ]'), '');

    return _pkcs1RSAPublicKey(base64.decode(data));
  } else if (pem.contains(_pkcs8RSAPublicHeader) &&
      pem.contains(_pkcs8RSAPublicFooter)) {
    final data = pem
        .substring(
          pem.indexOf(_pkcs8RSAPublicHeader) + _pkcs8RSAPublicHeader.length,
          pem.indexOf(_pkcs8RSAPublicFooter),
        )
        .replaceAll(RegExp(r'[\n\r ]'), '');

    return _pkcs8RSAPublicKey(base64.decode(data));
  } else {
    return null;
  }
}

/// Parse ECDSA private key from pem string
ECPrivateKey? parseECPrivateKeyPEM(String pem) {
  if (pem.contains(_sec1ECPrivateHeader) &&
      pem.contains(_sec1ECPrivateFooter)) {
    final data = pem
        .substring(
          pem.indexOf(_sec1ECPrivateHeader) + _sec1ECPrivateHeader.length,
          pem.indexOf(_sec1ECPrivateFooter),
        )
        .replaceAll(RegExp(r'[\n\r ]'), '');

    return _sec1ECPrivateKey(base64.decode(data));
  } else if (pem.contains(_pkcs8ECPrivateHeader) &&
      pem.contains(_pkcs8ECPrivateFooter)) {
    final data = pem
        .substring(
          pem.indexOf(_pkcs8ECPrivateHeader) + _pkcs8ECPrivateHeader.length,
          pem.indexOf(_pkcs8ECPrivateFooter),
        )
        .replaceAll(RegExp(r'[\n\r ]'), '');

    return _pkcs8ECPrivateKey(base64.decode(data));
  } else {
    return null;
  }
}

/// Parse ECDSA public key from pem string
ECPublicKey? parseECPublicKeyPEM(String pem) {
  if (pem.contains(_pkcs8ECPublicHeader) &&
      pem.contains(_pkcs8ECPublicFooter)) {
    final data = pem
        .substring(
          pem.indexOf(_pkcs8ECPublicHeader) + _pkcs8ECPublicHeader.length,
          pem.indexOf(_pkcs8ECPublicFooter),
        )
        .replaceAll(RegExp(r'[\n\r ]'), '');

    return _pkcs8ECPublicKey(base64.decode(data));
  } else {
    return null;
  }
}
