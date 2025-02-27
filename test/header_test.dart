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
        final iat = DateTime(2042);
        final exp = DateTime(2042).add(Duration(hours: 1));

        withClock(
          Clock.fixed(DateTime(2042)),
          () {
            final duration = Duration(hours: 1);
            final token = JWT({'foo': 'bar'}).sign(hsKey, expiresIn: duration);

            fakeAsync((async) {
              async.elapse(Duration(minutes: 30));
              expect(
                JWT.verify(token, hsKey).payload,
                equals({
                  'foo': 'bar',
                  'iat': iat.millisecondsSinceEpoch ~/ 1000,
                  'exp': exp.millisecondsSinceEpoch ~/ 1000,
                }),
              );
            });
          },
        );
      });

      test('should be valid when exp is disabled', () {
        final token =
            JWT({'foo': 'bar'}).sign(hsKey, expiresIn: Duration(hours: -1));

        expect(
          JWT.verify(token, hsKey, checkExpiresIn: false).payload,
          contains('foo'),
        );
      });
    });

    //----------------------//
    //   Not Before (nbf)   //
    //----------------------//
    group('nbf', () {
      test('should throw when token is not yet valid', () {
        final notBefore = Duration(hours: 1);
        final token = JWT({'foo': 'bar'}).sign(hsKey, notBefore: notBefore);

        expect(
          () => JWT.verify(token, hsKey),
          throwsA(isA<JWTNotActiveException>()),
        );
      });

      test('should be valid after nbf time', () {
        final iat = DateTime(2042);
        final nbf = iat.add(Duration(minutes: 30));

        withClock(
          Clock.fixed(DateTime(2042)),
          () {
            final token = JWT({'foo': 'bar'}).sign(
              hsKey,
              notBefore: Duration(minutes: 30),
            );

            fakeAsync((async) {
              async.elapse(Duration(minutes: 45));
              expect(
                JWT.verify(token, hsKey).payload,
                equals({
                  'foo': 'bar',
                  'iat': iat.millisecondsSinceEpoch ~/ 1000,
                  'nbf': nbf.millisecondsSinceEpoch ~/ 1000,
                }),
              );
            });
          },
        );
      });

      test('should be valid when nbf check is disabled', () {
        final token = JWT({'foo': 'bar'}).sign(
          hsKey,
          notBefore: Duration(hours: 1),
        );

        expect(
          JWT.verify(token, hsKey, checkNotBefore: false).payload,
          contains('foo'),
        );
      });

      //----------------------//
      //   Issued At (iat)   //
      //----------------------//
      group('iat', () {
        test('should have iat claim by default', () {
          final iat = DateTime(2042);

          withClock(Clock.fixed(iat), () {
            final token = JWT({'foo': 'bar'}).sign(hsKey);

            expect(
              JWT.verify(token, hsKey).payload,
              equals({
                'foo': 'bar',
                'iat': iat.millisecondsSinceEpoch ~/ 1000,
              }),
            );
          });
        });

        test('should be valid when iat is in the future', () {
          final futureIat = DateTime(2042).add(Duration(hours: 1));
          final token = JWT({
            'foo': 'bar',
            'iat': futureIat.millisecondsSinceEpoch ~/ 1000
          }).sign(hsKey);

          expect(
            JWT.verify(token, hsKey).payload,
            contains('foo'),
          );
        });
      });
    });
  });
}
