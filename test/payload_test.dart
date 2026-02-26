import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:test/test.dart';

import 'keys_const.dart';

void main() {
  group('JWT Payload', () {
    test('should always return the payload as dynamic', () {
      final jwt = JWT({'foo': 'bar'});
      expect(jwt.payload, isA<dynamic>());

      final jwt2 = JWT('foo');
      expect(jwt2.payload, isA<dynamic>());

      final jwt3 = JWT(1);
      expect(jwt3.payload, isA<dynamic>());
    });

    test('should assign the payload to the value given in the constructor', () {
      final jwt = JWT({'foo': 'bar'});
      expect(jwt.payload, equals({'foo': 'bar'}));
    });

    test('should return the payload as Map<String, dynamic>', () {
      final jwt = JWT({'foo': 'bar'});
      expect(jwt.payload, isA<Map<String, dynamic>>());
    });

    test('should return the payload as String', () {
      final jwt = JWT('foo');
      expect(jwt.payload, isA<String>());
    });

    test('should return the payload as Number', () {
      final jwt = JWT(1);
      expect(jwt.payload, isA<num>());
    });

    test('should be able to encode/decode Map<String, dynamic> payload', () {
      final jwt = JWT({'foo': 'bar'});
      final token = jwt.sign(hsKey);
      final verified = JWT.verify(token, hsKey);

      expect(verified.payload, equals(jwt.payload));
    });

    test('should be able to encode and decode String payload', () {
      final jwt = JWT('foo');
      final token = jwt.sign(hsKey);
      final verified = JWT.verify(token, hsKey);

      expect(verified.payload, equals(jwt.payload));
    });

    test('should be able to encode/decode number payload', () {
      final jwt = JWT(1);
      final token = jwt.sign(hsKey);
      final verified = JWT.verify(token, hsKey);

      expect(verified.payload, equals(jwt.payload));
    });

    test('should not be able to encode Map payload with non-String keys', () {
      final jwt = JWT({'foo': 'bar', 1: 'baz'});

      expect(
        () => jwt.sign(hsKey),
        throwsA(
          isA<AssertionError>().having(
            (e) => e.message,
            'message',
            contains(
              'If payload is a Map its must be a Map<String, dynamic>',
            ),
          ),
        ),
      );
    });
  });
}
