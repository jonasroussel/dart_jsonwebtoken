import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'package:clock/clock.dart';
import 'package:collection/collection.dart';

import 'algorithms.dart';
import 'exceptions.dart';
import 'helpers.dart';
import 'keys.dart';

class JWT {
  /// Verify a token.
  ///
  /// `key` must be
  /// - SecretKey with HMAC algorithm
  /// - RSAPublicKey with RSA algorithm
  /// - ECPublicKey with ECDSA algorithm
  /// - EdDSAPublicKey with EdDSA algorithm
  ///
  /// [issueAt] allows to verify that the token wasn't issued too long ago. The
  /// value is a timestamp (number of seconds since epoch) that is compared to
  /// the value of the 'iat' claim. Verification fails if the 'iat' claim is
  /// before [issueAt].
  static JWT verify(
    String token,
    JWTKey key, {
    bool checkHeaderType = true,
    bool checkExpiresIn = true,
    bool checkNotBefore = true,
    Duration? issueAt,
    Audience? audience,
    String? subject,
    String? issuer,
    String? jwtId,
  }) {
    try {
      final parts = token.split('.');
      final header = jsonBase64.decode(base64Padded(parts[0]));

      if (header == null || header is! Map<String, dynamic>) {
        throw JWTInvalidException('invalid header');
      }

      if (checkHeaderType && header['typ'] != 'JWT') {
        throw JWTInvalidException('not a jwt');
      }

      final algorithm = JWTAlgorithm.fromName(header['alg']);

      final body = utf8.encode(parts[0] + '.' + parts[1]);
      final signature = base64Url.decode(base64Padded(parts[2]));

      if (!algorithm.verify(key, Uint8List.fromList(body), signature)) {
        throw JWTInvalidException('invalid signature');
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
          final exp = DateTime.fromMillisecondsSinceEpoch(
            (payload['exp'] * 1000).toInt(),
          );
          if (exp.isBefore(clock.now())) {
            throw JWTExpiredException();
          }
        }

        // nbf
        if (checkNotBefore && payload.containsKey('nbf')) {
          final nbf = DateTime.fromMillisecondsSinceEpoch(
            (payload['nbf'] * 1000).toInt(),
          );
          if (nbf.isAfter(clock.now())) {
            throw JWTNotActiveException();
          }
        }

        // iat
        if (issueAt != null) {
          if (!payload.containsKey('iat')) {
            throw JWTInvalidException('invalid issue at');
          }
          final iat = DateTime.fromMillisecondsSinceEpoch(
            (payload['iat'] * 1000).toInt(),
          );
          final issueAtTime =
              DateTime.fromMillisecondsSinceEpoch(issueAt.inMilliseconds);
          // Verify that the token isn't expired
          if (iat.isBefore(issueAtTime)) {
            throw JWTInvalidException('expired issue at');
          }
        }

        // aud
        if (audience != null) {
          if (payload.containsKey('aud')) {
            if (payload['aud'] is String && payload['aud'] != audience.first) {
              throw JWTInvalidException('invalid audience');
            } else if (payload['aud'] is List &&
                !ListEquality().equals(payload['aud'], audience)) {
              throw JWTInvalidException('invalid audience');
            }
          } else {
            throw JWTInvalidException('invalid audience');
          }
        }

        // sub
        if (subject != null) {
          if (!payload.containsKey('sub') || payload['sub'] != subject) {
            throw JWTInvalidException('invalid subject');
          }
        }

        // iss
        if (issuer != null) {
          if (!payload.containsKey('iss') || payload['iss'] != issuer) {
            throw JWTInvalidException('invalid issuer');
          }
        }

        // jti
        if (jwtId != null) {
          if (!payload.containsKey('jti') || payload['jti'] != jwtId) {
            throw JWTInvalidException('invalid jwt id');
          }
        }

        return JWT(
          payload,
          header: header,
          audience: _parseAud(payload['aud']),
          issuer: payload['iss']?.toString(),
          subject: payload['sub']?.toString(),
          jwtId: payload['jti']?.toString(),
        );
      } else {
        return JWT(payload);
      }
    } catch (ex, stackTrace) {
      if (ex is Exception && ex is! JWTException) {
        throw JWTUndefinedException(ex, stackTrace);
      } else {
        rethrow;
      }
    }
  }

  /// Exactly like `verify`, just return null instead of throwing exceptions.
  static JWT? tryVerify(
    String token,
    JWTKey key, {
    bool checkHeaderType = true,
    bool checkExpiresIn = true,
    bool checkNotBefore = true,
    Duration? issueAt,
    Audience? audience,
    String? subject,
    String? issuer,
    String? jwtId,
  }) {
    try {
      return verify(
        token,
        key,
        checkHeaderType: checkHeaderType,
        checkExpiresIn: checkExpiresIn,
        checkNotBefore: checkNotBefore,
        issueAt: issueAt,
        audience: audience,
        subject: subject,
        issuer: issuer,
        jwtId: jwtId,
      );
    } catch (ex) {
      return null;
    }
  }

  /// Decode a token without checking its signature
  static JWT decode(String token) {
    try {
      final parts = token.split('.');
      var header = jsonBase64.decode(base64Padded(parts[0]));

      dynamic payload;

      try {
        payload = jsonBase64.decode(base64Padded(parts[1]));
      } catch (ex) {
        payload = utf8.decode(base64.decode(base64Padded(parts[1])));
      }

      if (header == null || header is! Map<String, dynamic>) {
        return JWT(payload);
      } else {
        return JWT(
          payload,
          header: header,
        );
      }
    } catch (ex, stackTrace) {
      if (ex is Exception && ex is! JWTException) {
        throw JWTUndefinedException(ex, stackTrace);
      } else {
        rethrow;
      }
    }
  }

  /// Exactly like `decode`, just return `null` instead of throwing exceptions.
  static JWT? tryDecode(String token) {
    try {
      return decode(token);
    } catch (ex) {
      return null;
    }
  }

  /// JSON Web Token
  JWT(
    this.payload, {
    this.audience,
    this.subject,
    this.issuer,
    this.jwtId,
    this.header,
  });

  /// Custom claims
  dynamic payload;

  /// Audience claim
  Audience? audience;

  /// Subject claim
  String? subject;

  /// Issuer claim
  String? issuer;

  /// JWT Id claim
  String? jwtId;

  /// JWT header
  Map<String, dynamic>? header;

  /// Sign and generate a new token.
  ///
  /// `key` must be
  /// - SecretKey with HMAC algorithm
  /// - RSAPrivateKey with RSA algorithm
  /// - ECPrivateKey with ECDSA algorithm
  /// - EdDSAPrivateKey with EdDSA algorithm
  String sign(
    JWTKey key, {
    JWTAlgorithm algorithm = JWTAlgorithm.HS256,
    Duration? expiresIn,
    Duration? notBefore,
    bool noIssueAt = false,
  }) {
    try {
      if (payload is Map<String, dynamic> || payload is Map<dynamic, dynamic>) {
        try {
          payload = Map<String, dynamic>.from(payload);

          if (!noIssueAt) payload['iat'] = secondsSinceEpoch(clock.now());
          if (expiresIn != null) {
            payload['exp'] = secondsSinceEpoch(clock.now().add(expiresIn));
          }
          if (notBefore != null) {
            payload['nbf'] = secondsSinceEpoch(clock.now().add(notBefore));
          }
          if (audience != null) payload['aud'] = audience!.toJson();
          if (subject != null) payload['sub'] = subject;
          if (issuer != null) payload['iss'] = issuer;
          if (jwtId != null) payload['jti'] = jwtId;
        } catch (ex) {
          assert(
            payload is Map<String, dynamic>,
            'If payload is a Map its must be a Map<String, dynamic>',
          );
        }
      }

      final tokenHeader = Map.from(header ?? {});
      tokenHeader.putIfAbsent('alg', () => algorithm.name);
      tokenHeader.putIfAbsent('typ', () => 'JWT');

      final b64Header = base64Unpadded(jsonBase64.encode(tokenHeader));

      String b64Payload;
      try {
        b64Payload = base64Unpadded(
          payload is String
              ? base64.encode(utf8.encode(payload))
              : jsonBase64.encode(payload),
        );
      } catch (ex) {
        throw JWTException(
          'invalid payload json format (Map keys must be String type)',
        );
      }

      final body = '$b64Header.$b64Payload';
      final signature = base64Unpadded(
        base64Url.encode(
          algorithm.sign(
            key,
            Uint8List.fromList(utf8.encode(body)),
          ),
        ),
      );

      return body + '.' + signature;
    } catch (ex, stackTrace) {
      if (ex is Exception && ex is! JWTException) {
        throw JWTUndefinedException(ex, stackTrace);
      } else {
        rethrow;
      }
    }
  }

  /// Exactly like `sign`, just return `null` instead of throwing exceptions.
  String? trySign(
    JWTKey key, {
    JWTAlgorithm algorithm = JWTAlgorithm.HS256,
    Duration? expiresIn,
    Duration? notBefore,
    bool noIssueAt = false,
  }) {
    try {
      return sign(
        key,
        algorithm: algorithm,
        expiresIn: expiresIn,
        notBefore: notBefore,
        noIssueAt: noIssueAt,
      );
    } catch (ex) {
      return null;
    }
  }

  static Audience? _parseAud(dynamic val) {
    if (val is String) {
      return Audience.one(val);
    } else if (val is List<String>) {
      return Audience(val);
    } else {
      return null;
    }
  }
}

/// Audience claim. Can contains one or more audience entry, used like a list
///
/// To get only one audience you can use `.first` getter (list cannot be empty)
///
/// To create a single audience you can use the factory `Audience.one('...')`.
class Audience extends ListBase<String> {
  Audience(this._audiences) : assert(_audiences.isNotEmpty);

  factory Audience.one(String val) => Audience([val]);

  final List<String> _audiences;

  @override
  int get length => _audiences.length;
  @override
  set length(int newLength) => _audiences.length = newLength;

  @override
  String operator [](int index) => _audiences[index];
  @override
  void operator []=(int index, String value) => _audiences[index] = value;

  @override
  void add(String value) => _audiences.add(value);
  @override
  void addAll(Iterable<String> all) => _audiences.addAll(all);

  dynamic toJson() {
    if (_audiences.length == 1) {
      return first;
    } else {
      return _audiences;
    }
  }
}
