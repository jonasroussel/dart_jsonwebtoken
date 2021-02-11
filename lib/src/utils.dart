import 'dart:convert';

import 'dart:typed_data';

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
