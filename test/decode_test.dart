import 'dart:convert';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:test/test.dart';

import 'keys_const.dart';

void main() {
  group('JWT.decode', () {
    test('decodes valid two-part token with JSON header and payload', () {
      final h = base64Url.encode(utf8.encode('{"alg":"HS256","typ":"JWT"}'));
      final p = base64Url
          .encode(utf8.encode('{"sub":"user123","iss":"https://example.com"}'));
      final token = '$h.$p';

      final jwt = JWT.decode(token);

      expect(jwt.payload, isA<Map<String, dynamic>>());
      expect(jwt.payload['sub'], 'user123');
      expect(jwt.payload['iss'], 'https://example.com');
      expect(jwt.subject, 'user123');
      expect(jwt.issuer, 'https://example.com');
      expect(jwt.header, isA<Map<String, dynamic>>());
      expect(jwt.header!['alg'], 'HS256');
      expect(jwt.header!['typ'], 'JWT');
    });

    test('decodes signed JWT (three-part token) using first two parts only',
        () {
      final jwt = JWT(
        {'sub': 'signed-user', 'iss': 'https://example.com'},
        header: {'alg': 'HS256', 'typ': 'JWT'},
      );
      final token = jwt.sign(hsKey);

      final decoded = JWT.decode(token);

      expect(decoded.payload['sub'], 'signed-user');
      expect(decoded.payload['iss'], 'https://example.com');
      expect(decoded.subject, 'signed-user');
      expect(decoded.issuer, 'https://example.com');
      expect(decoded.header!['alg'], 'HS256');
      expect(decoded.header!['typ'], 'JWT');
    });

    test('throws JWTInvalidException for single part', () {
      expect(
        () => JWT.decode('onlyonepart'),
        throwsA(isA<JWTInvalidException>().having(
          (e) => e.message,
          'message',
          'invalid token structure',
        )),
      );
    });

    test('throws JWTInvalidException when first part is empty', () {
      final p = base64Url.encode(utf8.encode('{"foo":"bar"}'));

      expect(
        () => JWT.decode('.$p'),
        throwsA(isA<JWTInvalidException>().having(
          (e) => e.message,
          'message',
          'invalid token structure',
        )),
      );
    });

    test('throws JWTInvalidException when second part is empty', () {
      final h = base64Url.encode(utf8.encode('{"alg":"HS256"}'));

      expect(
        () => JWT.decode('$h.'),
        throwsA(isA<JWTInvalidException>().having(
          (e) => e.message,
          'message',
          'invalid token structure',
        )),
      );
    });

    test('parses audience, issuer, subject, jwtId from payload', () {
      final jwt = JWT(
        {
          'aud': 'api',
          'iss': 'issuer',
          'sub': 'subject',
          'jti': 'id-1',
        },
        header: {'alg': 'HS256', 'typ': 'JWT'},
      );
      final token = jwt.sign(hsKey);

      final decoded = JWT.decode(token);

      expect(decoded.audience?.first, 'api');
      expect(decoded.issuer, 'issuer');
      expect(decoded.subject, 'subject');
      expect(decoded.jwtId, 'id-1');
    });

    test('parses array audience from payload', () {
      final jwt = JWT(
        {
          'aud': ['api', 'web']
        },
        header: {'alg': 'HS256', 'typ': 'JWT'},
      );
      final token = jwt.sign(hsKey);

      final decoded = JWT.decode(token);

      expect(decoded.audience, isNotNull);
      expect(decoded.audience!.length, 2);
      expect(decoded.audience![0], 'api');
      expect(decoded.audience![1], 'web');
    });

    test('allow string payload with null claims', () {
      final jwt = JWT(
        {'foo': 'bar'},
        header: {'alg': 'HS256', 'typ': 'JWT'},
      );
      final parts = jwt.sign(hsKey).split('.');
      parts[1] = base64Url.encode(utf8.encode('plain text'));
      final token = parts.join('.');

      final decoded = JWT.decode(token);

      expect(decoded.payload, 'plain text');
      expect(decoded.audience, isNull);
      expect(decoded.issuer, isNull);
      expect(decoded.subject, isNull);
      expect(decoded.jwtId, isNull);
    });

    test('header that is not a map results in null header', () {
      final jwt = JWT(
        {'foo': 'bar'},
        header: {'alg': 'HS256', 'typ': 'JWT'},
      );
      final parts = jwt.sign(hsKey).split('.');
      parts[0] = base64Url.encode(utf8.encode('"stringheader"'));
      final token = parts.join('.');

      final decoded = JWT.decode(token);

      expect(decoded.header, isNull);
      expect(decoded.payload, containsPair('foo', 'bar'));
    });

    test('invalid base64 in header throws JWTUndefinedException', () {
      final p = base64Url.encode(utf8.encode('{"foo":"bar"}'));

      expect(
        () => JWT.decode('!!!.$p'),
        throwsA(isA<JWTUndefinedException>()),
      );
    });
  });

  group('JWT.tryDecode', () {
    test('returns JWT for valid token', () {
      final jwt = JWT(
        {'sub': 'x'},
        header: {'alg': 'HS256', 'typ': 'JWT'},
      );
      final token = jwt.sign(hsKey);

      final decoded = JWT.tryDecode(token);

      expect(decoded, isNotNull);
      expect(decoded!.payload['sub'], 'x');
    });

    test('returns null for invalid token', () {
      expect(JWT.tryDecode('invalid'), isNull);
      expect(JWT.tryDecode('a.b.c'), isNull);
    });
  });
}
