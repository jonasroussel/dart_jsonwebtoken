import 'dart:convert';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

import './utils.dart';

class JWT {
  static JWT verify(String token, Key key) {
    final parts = token.split('.');

    final header = Map<String, dynamic>.from(jsonBase64.decode(base64Padded(parts[0])));

    if (header['typ'] != 'JWT') throw JWTInvalidError('not a jwt');

    final algorithm = JWTAlgorithm.fromName(header['alg']);

    if (parts.length < 3) throw JWTInvalidError('jwt malformated');

    final body = utf8.encode(parts[0] + '.' + parts[1]);
    final signature = base64Url.decode(base64Padded(parts[2]));

    if (!algorithm.verify(key, body, signature)) {
      throw JWTInvalidError('invalid signature');
    }

    final payload = Map<String, dynamic>.from(jsonBase64.decode(base64Padded(parts[1])));

    if (payload.containsKey('exp')) {
      final exp = DateTime.fromMillisecondsSinceEpoch(payload['exp'] * 1000);
      if (exp.isBefore(DateTime.now())) {
        throw JWTExpiredError();
      }
    }

    return JWT(
      payload: payload,
      audience: payload.remove('aud'),
      issuer: payload.remove('iss'),
      subject: payload.remove('sub'),
    );
  }

  JWT({
    this.payload = const {},
    this.audience,
    this.subject,
    this.issuer,
  });

  final Map<String, dynamic> payload;
  final String audience;
  final String subject;
  final String issuer;

  String sign(
    Key key, {
    JWTAlgorithm algorithm = JWTAlgorithm.HS256,
    Duration expiresIn,
    bool noTimestamp = false,
  }) {
    final header = {'alg': algorithm.name, 'typ': 'JWT'};

    if (!noTimestamp) payload['iat'] = secondsSinceEpoch(DateTime.now());
    if (expiresIn != null) payload['exp'] = secondsSinceEpoch(DateTime.now().add(expiresIn));
    if (audience != null) payload['aud'] = audience;
    if (subject != null) payload['sub'] = subject;
    if (issuer != null) payload['iss'] = issuer;

    final body = base64Unpadded(jsonBase64.encode(header)) + '.' + base64Unpadded(jsonBase64.encode(payload));
    final signature = base64Unpadded(base64Url.encode(algorithm.sign(key, utf8.encode(body))));

    return body + '.' + signature;
  }
}
