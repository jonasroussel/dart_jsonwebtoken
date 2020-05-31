import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:jsonwebtoken/jsonwebtoken.dart';

abstract class JWTAlgorithm {
  static const HS256 = HS256Algorithm();

  static JWTAlgorithm fromName(String name) {
    switch (name) {
      case 'HS256':
        return JWTAlgorithm.HS256;
      default:
        throw JWTInvalidError('unknown algorithm');
    }
  }

  const JWTAlgorithm();

  String get name;
  List<int> sign(String key, List<int> body);
  bool verify(String key, List<int> body, List<int> signature);
}

class HS256Algorithm extends JWTAlgorithm {
  const HS256Algorithm();

  @override
  String get name => 'HS256';

  @override
  List<int> sign(String key, List<int> body) {
    final hmac = Hmac(sha256, utf8.encode(key));
    return hmac.convert(body).bytes;
  }

  @override
  bool verify(String key, List<int> body, List<int> signature) {
    final actual = sign(key, body);

    if (actual.length != signature.length) return false;

    for (var i = 0; i < actual.length; i++) {
      if (actual[i] != signature[i]) return false;
    }

    return true;
  }
}
