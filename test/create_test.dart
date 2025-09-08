import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:test/test.dart';

void main() {
  group('Create a JWT', () {
    group('Payload', () {
      test('Constructor succeeds with a `String` payload', () {
        final jwt = JWT('Hello');

        expect(jwt.payload, 'Hello');
      });

      test('Constructor succeeds with a `Map<String, dynamic>` payload', () {
        final jwt = JWT(<String, dynamic>{'x': 1});

        expect(
          jwt.payload,
          isA<Map<String, dynamic>>(),
        );

        expect(
          jwt.payload,
          <String, dynamic>{'x': 1},
        );
      });

      test('Constructor succeeds with a `Map<String, String>` payload', () {
        final jwt = JWT(<String, String>{'key': 'value'});

        expect(
          jwt.payload,
          isA<Map<String, dynamic>>(),
        );

        expect(
          jwt.payload,
          <String, dynamic>{'key': 'value'},
        );
      });

      test('Constructor fails with an `int` payload', () {
        expect(
          () => JWT(3),
          throwsA(isA<TypeError>()),
        );
      });

      test('Constructor fails with an unexpected `Map` payload', () {
        expect(
          () => JWT({4: 5}),
          throwsA(isA<TypeError>()),
        );
      });
    });
  });
}
