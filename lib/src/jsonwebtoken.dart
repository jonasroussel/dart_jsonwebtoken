import 'dart:convert';

import 'package:crypto/crypto.dart';

class JWT {
  JWT({
    this.payload = const {},
    this.audience,
    this.subject,
    this.issuer,
  });

  static String secretKey = null;

  final _jsonToBase64Url = json.fuse(utf8.fuse(base64Url));

  final Map<String, dynamic> payload;
  final String audience;
  final String subject;
  final String issuer;

  String signedToken;

  String sign({
    String key,
    Duration expiresIn = null,
    bool noTimestamp = false,
  }) {
    if (key == null && JWT.secretKey != null) key = JWT.secretKey;
    assert(key != null);

    final header = {'alg': 'HS256', 'typ': 'JWT'};
    final algorithm = HS256Algorithm(key);

    // Creation timestamp
    if (!noTimestamp)
      payload['iat'] = DateTime.now();
    else
      payload.remove('iat');

    // Expiration timestamp
    if (expiresIn != null)
      payload['exp'] = DateTime.now().add(expiresIn);
    else
      payload.remove('exp');

    final body = _jsonToBase64Url.encode(header) + '.' + _jsonToBase64Url.encode(payload);
    final signature = base64Url.encode(algorithm.sign(utf8.encode(body)));

    return (signedToken = (body + '.' + signature));
  }

  static JWT verify(String token) {}
}

abstract class JWTAlgorithm {
  const JWTAlgorithm();

  String get name;
  List<int> sign(List<int> body);
  bool verify(List<int> body, List<int> signature);
}

class HS256Algorithm extends JWTAlgorithm {
  const HS256Algorithm(this.secretKey);

  final String secretKey;

  @override
  String get name => 'HS256';

  @override
  List<int> sign(List<int> body) {
    final hmac = Hmac(sha256, utf8.encode(secretKey));
    return hmac.convert(body).bytes;
  }

  @override
  bool verify(List<int> body, List<int> signature) {
    final actual = sign(body);

    if (actual.length != signature.length) return false;

    for (var i = 0; i < actual.length; i++) {
      if (actual[i] != signature[i]) return false;
    }

    return true;
  }
}
