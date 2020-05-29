import 'dart:convert';

import 'package:crypto/crypto.dart';

enum Algorithm {
  HS256,
  RS256,
}

class JWT {
  JWT({
    this.payload,
  });

  static String secretKey = null;

  Map<String, dynamic> payload;
  String audience;
  String subject;
  String issuer;

  String signedToken;

  String sign({
    String key,
    Algorithm algorithm = Algorithm.HS256,
    Duration expiresIn = const Duration(days: 7),
    bool noTimestamp = false,
  }) {
    if (key == null && JWT.secretKey != null) key = JWT.secretKey;
    assert(key != null);

    final headers = {'alg': algorithm.toString().split('.').last, 'typ': 'JWT'};
    final encodedHeader = _base64Unpadded(_jsonToBase64Url.encode(headers));
    final encodedPayload = _base64Unpadded(_jsonToBase64Url.encode(payload));

    final body = encodedHeader + '.' + encodedPayload;

    final signature = _base64Unpadded(base64Url.encode(_sign(body, key)));

    return body + '.' + signature;
  }

  List<int> _sign(String body, String key) {
    final hmac = Hmac(sha256, utf8.encode(key));
    return hmac.convert(utf8.encode(body)).bytes;
  }

  final _jsonToBase64Url = json.fuse(utf8.fuse(base64Url));

  String _base64Unpadded(String value) {
    if (value.endsWith('==')) return value.substring(0, value.length - 2);
    if (value.endsWith('=')) return value.substring(0, value.length - 1);
    return value;
  }

  static JWT verify(String token) {}
}
