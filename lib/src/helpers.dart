import 'dart:convert';
import 'dart:typed_data';

import 'package:clock/clock.dart';

import 'algorithms.dart';

final jsonBase64 = json.fuse(utf8.fuse(base64Url));

/// Removes base64 padding characters (`=`) from [value].
String base64Unpadded(String value) {
  if (value.endsWith('==')) return value.substring(0, value.length - 2);
  if (value.endsWith('=')) return value.substring(0, value.length - 1);
  return value;
}

/// Pads [value] with `=` so its length is a multiple of 4 (base64).
String base64Padded(String value) {
  final length = value.length;

  switch (length % 4) {
    case 2:
      return value.padRight(length + 2, '=');
    case 3:
      return value.padRight(length + 1, '=');
    default:
      return value;
  }
}

/// Returns the current time in UTC (uses [clock] for testability).
DateTime timeNowUTC() {
  return clock.now().toUtc();
}

/// Converts [time] to Unix seconds since epoch.
int secondsSinceEpoch(DateTime time) {
  return time.millisecondsSinceEpoch ~/ 1000;
}

/// Decodes [bytes] as a big-endian signed integer (two's complement).
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

/// Decodes [bytes] as a big-endian integer with explicit [sign] (-1, 0, or 1).
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

/// Encodes [v] as a little-endian byte list (unsigned).
Uint8List bigIntToBytes(BigInt v) {
  final b256 = BigInt.from(256);

  var bytes = <int>[];

  while (v.sign != 0) {
    bytes.add((v % b256).toInt());
    v = v ~/ b256;
  }

  return Uint8List.fromList(bytes);
}

/// Decodes [bytes] as a little-endian unsigned integer.
BigInt bigIntFromBytes(Uint8List bytes) {
  final b256 = BigInt.from(256);

  return bytes.fold(BigInt.zero, (a, b) => a * b256 + BigInt.from(b));
}

/// Splits [s] into substrings of length [chunkSize]
/// (last chunk may be shorter).
List<String> chunkString(String s, int chunkSize) {
  var chunked = <String>[];
  for (var i = 0; i < s.length; i += chunkSize) {
    var end = (i + chunkSize < s.length) ? i + chunkSize : s.length;
    chunked.add(s.substring(i, end));
  }
  return chunked;
}

/// Decodes [secret] to raw bytes: base64/base64url if [isBase64Encoded],
/// else UTF-8.
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

/// Maps OpenSSL/IANA curve names (e.g. prime256v1) to NIST names (e.g. P-256).
String curveOpenSSLToNIST(String curveName) {
  switch (curveName) {
    case "prime256v1":
    case "secp256r1":
      return "P-256";
    case "secp384r1":
      return "P-384";
    case "secp521r1":
      return "P-521";
    default:
      return curveName; // Return the original name if not found
  }
}

/// Maps NIST curve names (e.g. P-256) to OpenSSL names (e.g. prime256v1).
String curveNISTToOpenSSL(String curveName) {
  switch (curveName) {
    case "P-256":
      return "prime256v1";
    case "P-384":
      return "secp384r1";
    case "P-521":
      return "secp521r1";
    default:
      return curveName;
  }
}

/// Returns the ECDSA algorithm for the given curve name,
/// or null if unsupported.
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

/// Returns true if [a] and [b] are both null or contain the same elements
/// in order.
bool isListEquals<T>(List<T>? a, List<T>? b) {
  if (identical(a, b)) return true;
  if (a == null || b == null) return false;
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Compares two lists. If the lists have equal length this comparison will
/// iterate all elements, thus taking a fixed amount of time making timing
/// attacks harder.
bool fixedTimeBytesEquals(Uint8List? a, Uint8List? b) {
  if (a == null || b == null) return a == b;
  if (a.length != b.length) return false;
  var e = 0;
  for (var i = 0; i < a.length; i++) {
    e |= a[i] ^ b[i];
  }
  return e == 0;
}
