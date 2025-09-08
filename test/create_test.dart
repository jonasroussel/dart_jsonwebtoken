import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:test/test.dart';

void main() {
  group('Create a JWT', () {
    group('Payload', () {
      group('Map<String, String>', () {
        test('Works as a payload, but gets converted', () {
          final payload = <String, String>{
            'foo': 'bar',
          };

          final jwt = JWT(payload);

          expect(jwt.payload, isA<Map<String, dynamic>>());
          expect(jwt.payload, payload);
        });
      });

      group('Map<String, dynamic>', () {
        test('Works as a payload', () {
          final payload = <String, dynamic>{
            'foo': 'bar',
            'iat': 1234,
          };

          final jwt = JWT(payload);

          expect(jwt.payload, isA<Map<String, dynamic>>());
          expect(jwt.payload, payload);
        });

        test('Gets copied internally', () {
          final payload = <String, dynamic>{
            'foo': 'bar',
            'iat': 1234,
          };

          final jwt = JWT(payload);

          expect(jwt.payload, isA<Map<String, dynamic>>());
          expect(jwt.payload, payload);
          expect(identical(jwt.payload, payload), isFalse);

          payload['new_key'] = true;

          expect(jwt.payload, hasLength(2));
        });
      });

      group('Map<int, dynamic>', () {
        test('Does not work as a payload', () {
          final payload = <int, dynamic>{
            123: 'bar',
          };

          expect(
            () => JWT(payload),
            throwsA(isA<TypeError>()),
          );
        });
      });

      group('String', () {
        test('Works as a payload', () {
          final payload = 'asdf123';

          final jwt = JWT(payload);

          expect(jwt.payload, payload);
        });
      });

      group('int', () {
        test('Does not work as a payload', () {
          final payload = 1234;

          expect(
            () => JWT(payload),
            throwsA(isA<Exception>()),
          );
        });
      });
    });
  });
}
