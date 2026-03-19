// ignore: lines_longer_than_80_chars
// ignore_for_file: constant_identifier_names, avoid_classes_with_only_static_members
import 'dart:convert';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:pointycastle/asn1/object_identifiers.dart';
import 'package:pointycastle/ecc/ecc_fp.dart' as ecc_fp;
import 'package:pointycastle/pointycastle.dart';

import 'helpers.dart';

abstract class KeyParser {
  static const BEGIN_PRIVATE_KEY = '-----BEGIN PRIVATE KEY-----';
  static const END_PRIVATE_KEY = '-----END PRIVATE KEY-----';

  static const BEGIN_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----';
  static const END_PUBLIC_KEY = '-----END PUBLIC KEY-----';

  static const BEGIN_EC_PRIVATE_KEY = '-----BEGIN EC PRIVATE KEY-----';
  static const END_EC_PRIVATE_KEY = '-----END EC PRIVATE KEY-----';

  static const BEGIN_EC_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----';
  static const END_EC_PUBLIC_KEY = '-----END PUBLIC KEY-----';

  static const BEGIN_RSA_PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----';
  static const END_RSA_PRIVATE_KEY = '-----END RSA PRIVATE KEY-----';

  static const BEGIN_RSA_PUBLIC_KEY = '-----BEGIN RSA PUBLIC KEY-----';
  static const END_RSA_PUBLIC_KEY = '-----END RSA PUBLIC KEY-----';

  //-------------//
  // RSA Parsing //
  //-------------//

  static RSAPrivateKey rsaPrivateKeyFromPEM(String pem, {bool pkcs1 = false}) {
    final bytes = bytesFromPEM(pem);

    if (pkcs1) {
      return rsaPrivateKeyPKCS1(bytes);
    } else {
      return rsaPrivateKey(bytes);
    }
  }

  static RSAPrivateKey rsaPrivateKey(Uint8List bytes) {
    var asn1Parser = ASN1Parser(bytes);
    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
    final privateKey = topLevelSeq.elements![2];

    asn1Parser = ASN1Parser(privateKey.valueBytes);
    final pkSeq = asn1Parser.nextObject() as ASN1Sequence;

    final modulus = pkSeq.elements![1] as ASN1Integer;
    final privateExponent = pkSeq.elements![3] as ASN1Integer;
    final p = pkSeq.elements![4] as ASN1Integer;
    final q = pkSeq.elements![5] as ASN1Integer;

    return RSAPrivateKey(
      modulus.integer!,
      privateExponent.integer!,
      p.integer,
      q.integer,
    );
  }

  static RSAPrivateKey rsaPrivateKeyPKCS1(Uint8List bytes) {
    final asn1Parser = ASN1Parser(bytes);
    final pkSeq = asn1Parser.nextObject() as ASN1Sequence;

    final modulus = pkSeq.elements![1] as ASN1Integer;
    final privateExponent = pkSeq.elements![3] as ASN1Integer;
    final p = pkSeq.elements![4] as ASN1Integer;
    final q = pkSeq.elements![5] as ASN1Integer;

    return RSAPrivateKey(
      modulus.integer!,
      privateExponent.integer!,
      p.integer,
      q.integer,
    );
  }

  static RSAPublicKey rsaPublicKeyFromPEM(String pem, {bool pkcs1 = false}) {
    final bytes = bytesFromPEM(pem);

    if (pkcs1) {
      return rsaPublicKeyPKCS1(bytes);
    } else {
      return rsaPublicKey(bytes);
    }
  }

  static RSAPublicKey rsaPublicKey(Uint8List bytes) {
    final asn1Parser = ASN1Parser(bytes);
    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    final ASN1Sequence publicKeySeq;
    if (topLevelSeq.elements![1].runtimeType == ASN1BitString) {
      final publicKeyBitString = topLevelSeq.elements![1] as ASN1BitString;

      final publicKeyAsn = ASN1Parser(
        publicKeyBitString.stringValues as Uint8List?,
      );
      publicKeySeq = publicKeyAsn.nextObject() as ASN1Sequence;
    } else {
      publicKeySeq = topLevelSeq;
    }

    final modulus = publicKeySeq.elements![0] as ASN1Integer;
    final exponent = publicKeySeq.elements![1] as ASN1Integer;

    return RSAPublicKey(modulus.integer!, exponent.integer!);
  }

  static RSAPublicKey rsaPublicKeyPKCS1(Uint8List bytes) {
    final publicKeyAsn = ASN1Parser(bytes);
    final publicKeySeq = publicKeyAsn.nextObject() as ASN1Sequence;
    final modulus = publicKeySeq.elements![0] as ASN1Integer;
    final exponent = publicKeySeq.elements![1] as ASN1Integer;

    return RSAPublicKey(modulus.integer!, exponent.integer!);
  }

  //---------------//
  // ECDSA Parsing //
  //---------------//

  static ECPrivateKey ecPrivateKeyFromPEM(String pem, {bool pkcs1 = false}) {
    final bytes = bytesFromPEM(pem);

    if (pkcs1) {
      return ecPrivateKeyPKCS1(bytes);
    } else {
      return ecPrivateKey(bytes);
    }
  }

  static ECPrivateKey ecPrivateKey(Uint8List bytes) {
    var asn1Parser = ASN1Parser(bytes);
    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    String? curveName;

    // Parse the PKCS8 format
    final innerSeq = topLevelSeq.elements!.elementAt(1) as ASN1Sequence;
    final b2 = innerSeq.elements!.elementAt(1) as ASN1ObjectIdentifier;
    final b2Data = b2.objectIdentifierAsString;
    final b2Curvedata = ObjectIdentifiers.getIdentifierByIdentifier(b2Data);
    if (b2Curvedata != null) {
      curveName = b2Curvedata['readableName'] as String?;
    }

    final octetString = topLevelSeq.elements!.elementAt(2) as ASN1OctetString;
    asn1Parser = ASN1Parser(octetString.valueBytes);
    final octetStringSeq = asn1Parser.nextObject() as ASN1Sequence;
    final octetStringKeyData =
        octetStringSeq.elements!.elementAt(1) as ASN1OctetString;

    final x = octetStringKeyData.valueBytes!;

    return ECPrivateKey(
      osp2i(x),
      ECDomainParameters(curveName ?? 'prime256v1'),
    );
  }

  static ECPrivateKey ecPrivateKeyPKCS1(Uint8List bytes) {
    final asn1Parser = ASN1Parser(bytes);
    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    String? curveName;

    // Parse the SEC1 format
    final privateKeyAsOctetString =
        topLevelSeq.elements!.elementAt(1) as ASN1OctetString;
    final choice = topLevelSeq.elements!.elementAt(2);
    final s = ASN1Sequence();
    final parser = ASN1Parser(choice.valueBytes);
    while (parser.hasNext()) {
      s.add(parser.nextObject());
    }

    final curveNameOi = s.elements!.elementAt(0) as ASN1ObjectIdentifier;
    final data = ObjectIdentifiers.getIdentifierByIdentifier(
      curveNameOi.objectIdentifierAsString,
    );
    if (data != null) {
      curveName = data['readableName'] as String?;
    }

    final x = privateKeyAsOctetString.valueBytes!;

    return ECPrivateKey(
      osp2i(x),
      ECDomainParameters(curveName ?? 'prime256v1'),
    );
  }

  static ECPublicKey ecPublicKeyFromPEM(String pem) {
    final bytes = bytesFromPEM(pem);

    return ecPublicKey(bytes);
  }

  static ECPublicKey ecPublicKey(Uint8List bytes) {
    var pubBytes = bytes;
    if (pubBytes.elementAt(0) == 0) {
      pubBytes = pubBytes.sublist(1);
    }
    final asn1Parser = ASN1Parser(pubBytes);
    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    final algorithmIdentifierSequence =
        topLevelSeq.elements![0] as ASN1Sequence;
    final curveNameOi =
        algorithmIdentifierSequence.elements!.elementAt(1)
            as ASN1ObjectIdentifier;
    String? curveName;
    final data = ObjectIdentifiers.getIdentifierByIdentifier(
      curveNameOi.objectIdentifierAsString,
    );
    if (data != null) {
      curveName = data['readableName'] as String?;
    }

    final subjectPublicKey = topLevelSeq.elements![1] as ASN1BitString;
    var compressed = false;
    var keyPubBytes = subjectPublicKey.valueBytes!;
    if (keyPubBytes.elementAt(0) == 0) {
      keyPubBytes = keyPubBytes.sublist(1);
    }

    // Looks good so far!
    final firstByte = keyPubBytes.elementAt(0);
    if (firstByte != 4) {
      compressed = true;
    }
    final x = keyPubBytes.sublist(1, (keyPubBytes.length / 2).round());
    final y = keyPubBytes.sublist(1 + x.length, keyPubBytes.length);
    final params = ECDomainParameters(curveName ?? 'prime256v1');
    final bigX = decodeBigIntWithSign(1, x);
    final bigY = decodeBigIntWithSign(1, y);
    final pubKey = ECPublicKey(
      ecc_fp.ECPoint(
        params.curve as ecc_fp.ECCurve,
        params.curve.fromBigInteger(bigX) as ecc_fp.ECFieldElement?,
        params.curve.fromBigInteger(bigY) as ecc_fp.ECFieldElement?,
        compressed,
      ),
      params,
    );
    return pubKey;
  }

  //---------------//
  // EdDSA Parsing //
  //---------------//

  static ed.PrivateKey edPrivateKeyFromPEM(String pem) {
    final bytes = bytesFromPEM(pem);
    return edPrivateKey(bytes);
  }

  static ed.PrivateKey edPrivateKey(Uint8List bytes) {
    final asn1Parser = ASN1Parser(bytes);
    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    final octetString = topLevelSeq.elements!.elementAt(2) as ASN1OctetString;

    return ed.newKeyFromSeed(octetString.valueBytes!.sublist(2));
  }

  static ed.PublicKey edPublicKeyFromPEM(String pem) {
    final bytes = bytesFromPEM(pem);
    return edPublicKey(bytes);
  }

  static ed.PublicKey edPublicKey(Uint8List bytes) {
    final asn1Parser = ASN1Parser(bytes);
    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    final bitString = topLevelSeq.elements!.elementAt(1) as ASN1BitString;

    return ed.PublicKey(bitString.valueBytes!.sublist(1));
  }

  //--------------//
  // PEM to Bytes //
  //--------------//

  static Uint8List publicKeyBytesFromCertificate(String pem) {
    final bytes = bytesFromPEM(pem);
    final asn1Parser = ASN1Parser(bytes);

    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
    final certSq = topLevelSeq.elements!.elementAt(0) as ASN1Sequence;

    final int element;
    if (certSq.elements!.elementAt(0) is ASN1Integer) {
      element = -1;
    } else {
      element = 0;
    }

    final pubKeySequence = certSq.elements!.elementAt(element + 6);

    return pubKeySequence.encodedBytes ?? Uint8List(0);
  }

  static Uint8List bytesFromPEM(String pem) {
    final lines = LineSplitter.split(
      pem,
    ).map((line) => line.trim()).where((line) => line.isNotEmpty).toList();

    final base64Data = lines.sublist(1, lines.length - 1).join();

    return Uint8List.fromList(base64Decode(base64Data));
  }

  //------------------//
  // Helper Functions //
  //------------------//

  static BigInt osp2i(Iterable<int> bytes, {Endian endian = Endian.big}) {
    var result = BigInt.from(0);
    final byteList = endian == Endian.little ? bytes.toList().reversed : bytes;

    for (final byte in byteList) {
      result = result << 8;
      result |= BigInt.from(byte);
    }

    return result;
  }
}
