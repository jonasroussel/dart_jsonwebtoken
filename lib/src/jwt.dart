import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

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
  /// value is a timestamp (number of seconds since epoch) in UTC if
  /// [issueAtUtc] is true, it is compared to the value of the 'iat' claim.
  /// Verification fails if the 'iat' claim is before [issueAt].
  ///
  /// If the embedded `payload` is not a JSON map (but rather just a plain string),
  /// none of the verifications are executed. In that case only the signature is verified.
  static JWT verify(
    String token,
    JWTKey key, {
    bool checkHeaderType = true,
    bool checkExpiresIn = true,
    bool checkNotBefore = true,
    Duration? issueAt,
    bool issueAtUtc = true,
    Audience? audience,
    String? subject,
    String? issuer,
    String? jwtId,
  }) {
    try {
      final parts = token.split('.');

      if (parts.length != 3) {
        throw JWTInvalidException(
          'token does not use JWS Compact Serialization',
        );
      }

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

      Object payload;

      try {
        payload =
            jsonBase64.decode(base64Padded(parts[1])) as Map<String, dynamic>;
      } catch (ex) {
        payload = utf8.decode(base64Url.decode(base64Padded(parts[1])));
      }

      if (payload is Map) {
        // exp
        if (checkExpiresIn && payload.containsKey('exp')) {
          final exp = DateTime.fromMillisecondsSinceEpoch(
            (payload['exp'] * 1000).toInt(),
            isUtc: true,
          );
          if (exp.isBefore(timeNowUTC())) {
            throw JWTExpiredException();
          }
        }

        // nbf
        if (checkNotBefore && payload.containsKey('nbf')) {
          final nbf = DateTime.fromMillisecondsSinceEpoch(
            (payload['nbf'] * 1000).toInt(),
            isUtc: true,
          );
          if (nbf.isAfter(timeNowUTC())) {
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
            isUtc: true,
          );
          final issueAtTime = DateTime.fromMillisecondsSinceEpoch(
            issueAt.inMilliseconds,
            isUtc: issueAtUtc,
          );
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
                !isListEquals(payload['aud'], audience)) {
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
  ///
  /// This also sets [JWT.audience], [JWT.subject], [JWT.issuer], and
  /// [JWT.jwtId] even though they are not verified. Use with caution.
  ///
  /// This methods only supports map payloads. For `String` payloads use `verify`.
  static JWT decode(String token) {
    try {
      final parts = token.split('.');
      final header = jsonBase64.decode(base64Padded(parts[0]));

      final payload =
          (jsonBase64.decode(base64Padded(parts[1])) as Map<String, dynamic>);

      final audiance = _parseAud(payload['aud']);
      final issuer = payload['iss']?.toString();
      final subject = payload['sub']?.toString();
      final jwtId = payload['jti']?.toString();

      return JWT(
        payload,
        header: header is! Map<String, dynamic> ? null : header,
        audience: audiance,
        issuer: issuer,
        subject: subject,
        jwtId: jwtId,
      );
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
    Object payload, {
    this.audience,
    this.subject,
    this.issuer,
    this.jwtId,
    this.header,
  }) {
    this.payload = payload;
  }

  late Object _payload;

  /// The token's payload, either as a `Map<String, dynamic>` or plain `String`
  /// (in case it was not a JSON-encoded map).
  ///
  /// If it's a map, it has all claims, containing the utilized registered claims
  /// as well custom ones added.
  Object get payload => _payload;

  void set payload(Object value) {
    if (value is String) {
      _payload = value;
    } else if (value is Map) {
      _payload = Map<String, dynamic>.from(value);
    } else {
      throw Exception(
        'Unexpected `payload` type `${value.runtimeType}`, must be either `String` or `Map<String, *>`',
      );
    }
  }

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
      var payload = this.payload;
      if (payload is Map<String, dynamic>) {
        try {
          payload = Map<String, dynamic>.from(payload);

          if (!noIssueAt) {
            payload['iat'] = secondsSinceEpoch(timeNowUTC());
          }
          if (expiresIn != null) {
            payload['exp'] = secondsSinceEpoch(timeNowUTC().add(expiresIn));
          }
          if (notBefore != null) {
            payload['nbf'] = secondsSinceEpoch(timeNowUTC().add(notBefore));
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
              ? base64Url.encode(utf8.encode(payload))
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
