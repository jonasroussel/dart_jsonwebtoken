import 'dart:convert';
import 'dart:typed_data';

import 'algorithms.dart';

final jsonBase64 = json.fuse(utf8.fuse(base64Url));

String base64Unpadded(String value) {
  if (value.endsWith('==')) return value.substring(0, value.length - 2);
  if (value.endsWith('=')) return value.substring(0, value.length - 1);
  return value;
}

String base64Padded(String value) {
  final lenght = value.length;

  switch (lenght % 4) {
    case 2:
      return value.padRight(lenght + 2, '=');
    case 3:
      return value.padRight(lenght + 1, '=');
    default:
      return value;
  }
}

int secondsSinceEpoch(DateTime time) {
  return time.millisecondsSinceEpoch ~/ 1000;
}

BigInt decodeBigInt(List<int> bytes) {
  var negative = bytes.isNotEmpty && bytes[0] & 0x80 == 0x80;

  BigInt result;

  if (bytes.length == 1) {
    result = BigInt.from(bytes[0]);
  } else {
    result = BigInt.zero;

    for (var i = 0; i < bytes.length; i++) {
      var item = bytes[bytes.length - i - 1];
      result |= (BigInt.from(item) << (8 * i));
    }
  }

  if (result == BigInt.zero) return BigInt.zero;

  return negative ? result.toSigned(result.bitLength) : result;
}

BigInt decodeBigIntWithSign(int sign, List<int> bytes) {
  if (sign == 0) return BigInt.zero;

  BigInt result;

  if (bytes.length == 1) {
    result = BigInt.from(bytes[0]);
  } else {
    result = BigInt.zero;

    for (var i = 0; i < bytes.length; i++) {
      var item = bytes[bytes.length - i - 1];
      result |= (BigInt.from(item) << (8 * i));
    }
  }

  if (result == BigInt.zero) return BigInt.zero;

  return sign < 0
      ? result.toSigned(result.bitLength)
      : result.toUnsigned(result.bitLength);
}

Uint8List bigIntToBytes(BigInt v) {
  final _b256 = BigInt.from(256);

  var bytes = <int>[];

  while (v.sign != 0) {
    bytes.add((v % _b256).toInt());
    v = v ~/ _b256;
  }

  return Uint8List.fromList(bytes);
}

BigInt bigIntFromBytes(Uint8List bytes) {
  final _b256 = BigInt.from(256);

  return bytes.fold(BigInt.zero, (a, b) => a * _b256 + BigInt.from(b));
}

List<String> chunkString(String s, int chunkSize) {
  var chunked = <String>[];
  for (var i = 0; i < s.length; i += chunkSize) {
    var end = (i + chunkSize < s.length) ? i + chunkSize : s.length;
    chunked.add(s.substring(i, end));
  }
  return chunked;
}

Uint8List decodeHMACSecret(String secret, bool isBase64Encoded) {
  if (isBase64Encoded) {
    if (RegExp(r'-|_+').hasMatch(secret)) {
      return base64Url.decode(secret);
    } else {
      return base64.decode(secret);
    }
  } else {
    return utf8.encode(secret);
  }
}

String curveOpenSSLToNIST(String curveName) {
  switch (curveName) {
    case "prime256v1":
    case "secp256r1":
      return "P-256";
    case "secp384r1":
      return "P-384";
    case "secp521r1":
      return "P-521";
    case "secp192r1":
      return "P-192";
    case "secp224r1":
      return "P-224";
    default:
      return curveName; // Return the original name if not found
  }
}

ECDSAAlgorithm? ecCurveToAlgorithm(String curveName) {
  switch (curveName) {
    case "P-256":
      return JWTAlgorithm.ES256;
    case "P-384":
      return JWTAlgorithm.ES384;
    case "P-521":
      return JWTAlgorithm.ES512;
    case "secp256k1":
      return JWTAlgorithm.ES256K;
    default:
      return null;
  }
}
