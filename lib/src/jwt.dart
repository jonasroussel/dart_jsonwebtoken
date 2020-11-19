import 'dart:convert';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

import './utils.dart';

class JWT {
  /// Verify a token.
  ///
  /// `key` must be
  /// - SecretKey with HS256 algorithm
  /// - PublicKey with RS256 algorithm
  static JWT verify(
    String token,
    Key key, {
    bool checkHeaderType = true,
    bool checkExpiresIn = true,
    bool checkNotBefore = true,
    bool throwUndefinedErrors = false,
    Duration issueAt,
    String audience,
    String subject,
    String issuer,
    String jwtId,
  }) {
    try {
      final parts = token.split('.');

      Map<String, dynamic> header = jsonBase64.decode(base64Padded(parts[0]));

      if (checkHeaderType && header['typ'] != 'JWT') {
        throw JWTInvalidError('not a jwt');
      }

      final algorithm = JWTAlgorithm.fromName(header['alg']);

      final body = utf8.encode(parts[0] + '.' + parts[1]);
      final signature = base64Url.decode(base64Padded(parts[2]));

      if (!algorithm.verify(key, body, signature)) {
        throw JWTInvalidError('invalid signature');
      }

      dynamic payload;

      try {
        payload = jsonBase64.decode(base64Padded(parts[1]));
      } catch (ex) {
        payload = utf8.decode(base64.decode(base64Padded(parts[1])));
      }

      if (payload is Map) {
        // exp
        if (checkExpiresIn && payload.containsKey('exp')) {
          final exp =
              DateTime.fromMillisecondsSinceEpoch(payload['exp'] * 1000);
          if (exp.isBefore(DateTime.now())) {
            throw JWTExpiredError();
          }
        }

        // nbf
        if (checkNotBefore && payload.containsKey('nbf')) {
          final nbf =
              DateTime.fromMillisecondsSinceEpoch(payload['nbf'] * 1000);
          if (nbf.isAfter(DateTime.now())) {
            throw JWTNotActiveError();
          }
        }

        // iat
        if (issueAt != null) {
          if (!payload.containsKey('iat')) {
            throw JWTInvalidError('invalid issue at');
          }
          final iat =
              DateTime.fromMillisecondsSinceEpoch(payload['iat'] * 1000);
          if (!iat.isAtSameMomentAs(DateTime.now())) {
            throw JWTInvalidError('invalid issue at');
          }
        }

        // aud
        if (audience != null) {
          if (!payload.containsKey('aud') || payload['aud'] != audience) {
            throw JWTInvalidError('invalid audience');
          }
        }

        // sub
        if (subject != null) {
          if (!payload.containsKey('sub') || payload['sub'] != subject) {
            throw JWTInvalidError('invalid subject');
          }
        }

        // iss
        if (issuer != null) {
          if (!payload.containsKey('iss') || payload['iss'] != issuer) {
            throw JWTInvalidError('invalid issuer');
          }
        }

        // jti
        if (jwtId != null) {
          if (!payload.containsKey('jti') || payload['jti'] != jwtId) {
            throw JWTInvalidError('invalid jwt id');
          }
        }

        return JWT(
          payload,
          audience: payload.remove('aud'),
          issuer: payload.remove('iss'),
          subject: payload.remove('sub'),
          jwtId: payload.remove('jti'),
        );
      } else {
        return JWT(payload);
      }
    } catch (ex) {
      if (throwUndefinedErrors) {
        rethrow;
      } else {
        throw JWTInvalidError('invalid token');
      }
    }
  }

  /// JSON Web Token
  JWT(
    this.payload, {
    this.audience,
    this.subject,
    this.issuer,
    this.jwtId,
  });

  /// Custom claims
  dynamic payload;

  /// Audience claim
  String audience;

  /// Subject claim
  String subject;

  /// Issuer claim
  String issuer;

  /// JWT Id claim
  String jwtId;

  /// Sign and generate a new token.
  ///
  /// `key` must be
  /// - SecretKey with HS256 algorithm
  /// - PrivateKey with RS256 algorithm
  String sign(
    Key key, {
    JWTAlgorithm algorithm = JWTAlgorithm.HS256,
    Duration expiresIn,
    Duration notBefore,
    bool noIssueAt = false,
  }) {
    final header = {'alg': algorithm.name, 'typ': 'JWT'};

    if (payload is Map) {
      if (!noIssueAt) payload['iat'] = secondsSinceEpoch(DateTime.now());
      if (expiresIn != null) {
        payload['exp'] = secondsSinceEpoch(DateTime.now().add(expiresIn));
      }
      if (notBefore != null) {
        payload['nbf'] = secondsSinceEpoch(DateTime.now().add(notBefore));
      }
      if (audience != null) payload['aud'] = audience;
      if (subject != null) payload['sub'] = subject;
      if (issuer != null) payload['iss'] = issuer;
      if (jwtId != null) payload['jti'] = jwtId;
    }

    final b64Header = base64Unpadded(jsonBase64.encode(header));
    final b64Payload = base64Unpadded(
      payload is String
          ? base64.encode(utf8.encode(payload))
          : jsonBase64.encode(payload),
    );

    final body = '${b64Header}.${b64Payload}';
    final signature = base64Unpadded(
      base64Url.encode(
        algorithm.sign(
          key,
          utf8.encode(body),
        ),
      ),
    );

    return body + '.' + signature;
  }
}
