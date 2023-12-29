import 'package:clock/clock.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:fake_async/fake_async.dart';
import 'package:test/test.dart';

final hsKey = SecretKey('secret passphrase');

void main() {
  group("JWT Header", () {
    //--------------------//
    //  Expiration (exp)  //
    //--------------------//
    group('exp', () {
      test('should be expired', () {
        final duration = Duration(hours: 1);
        final token = JWT({'foo': 'bar'}).sign(hsKey, expiresIn: duration);

        fakeAsync((async) {
          async.elapse(duration);
          expect(
            () => JWT.verify(token, hsKey),
            throwsA(isA<JWTExpiredException>()),
          );
        });
      });

      test('should be still valid', () {
        withClock(
          Clock.fixed(DateTime(2023)),
          () {
            final duration = Duration(hours: 1);
            final token = JWT({'foo': 'bar'}).sign(hsKey, expiresIn: duration);

            fakeAsync((async) {
              async.elapse(Duration(minutes: 30));
              expect(
                JWT.verify(token, hsKey).payload,
                equals({
                  'foo': 'bar',
                  'iat': DateTime(2023).millisecondsSinceEpoch ~/ 1000,
                  'exp': DateTime(2023).add(Duration(hours: 1)).millisecondsSinceEpoch ~/ 1000,
                }),
              );
            });
          },
        );
      });
    });
  });
}
