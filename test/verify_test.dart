import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:test/test.dart';

import 'keys_const.dart';

void main() {
  group('Verify a JWT', () {
    //--------//
    // Claims //
    //--------//
    group('Claims', () {
      group('iat', () {
        final oneMinuteAgo = DateTime.now().subtract(Duration(minutes: 1));
        test('exact issueAt passes validation', () {
          final jwt = JWT(
            {
              'foo': 'bar',
              'iat': oneMinuteAgo.millisecondsSinceEpoch ~/ 1000,
            },
          );
          final verified = JWT.tryVerify(
            jwt.sign(hsKey, noIssueAt: true),
            hsKey,
            issueAt:
                Duration(seconds: oneMinuteAgo.millisecondsSinceEpoch ~/ 1000),
          );
          expect(verified, isNotNull);
        });
        test('expired issueAt fails validation', () {
          final jwt = JWT(
            {
              'foo': 'bar',
              'iat': oneMinuteAgo
                      .subtract(Duration(seconds: 1))
                      .millisecondsSinceEpoch ~/
                  1000,
            },
          );
          final verified = JWT.tryVerify(
            jwt.sign(hsKey, noIssueAt: true),
            hsKey,
            issueAt:
                Duration(seconds: oneMinuteAgo.millisecondsSinceEpoch ~/ 1000),
          );
          expect(verified, isNull);
        });
        test('fresher issueAt passes validation', () {
          final jwt = JWT(
            {
              'foo': 'bar',
              'iat': oneMinuteAgo
                      .add(Duration(seconds: 1))
                      .millisecondsSinceEpoch ~/
                  1000,
            },
          );
          final verified = JWT.tryVerify(
            jwt.sign(hsKey, noIssueAt: true),
            hsKey,
            issueAt:
                Duration(seconds: oneMinuteAgo.millisecondsSinceEpoch ~/ 1000),
          );
          expect(verified, isNotNull);
        });
      });
    });

    //------//
    // HMAC //
    //------//
    group('HMAC', () {
      test('.verify HS256', () {
        final token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' +
            '.eyJmb28iOiJiYXIifQ' +
            '.NGVtp-VylRDt194QX0dDtpO6npY0je5nJvmF5w9MsS4';

        final jwt = JWT.tryVerify(token, hsKey);

        expect(jwt, isNotNull);
        expect(jwt?.payload, equals({'foo': 'bar'}));
      });
      test('.verify HS384', () {
        final token = 'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9' +
            '.eyJmb28iOiJiYXIifQ' +
            '.DGsoLHrTRkgC-57QAcDQOyg1EcgonMG2x_zb1GsPR3hBfGxedHzd82erWkGpq7LZ';

        final jwt = JWT.tryVerify(token, hsKey);

        expect(jwt, isNotNull);
        expect(jwt?.payload, equals({'foo': 'bar'}));
      });
      test('.verify HS512', () {
        final token = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9' +
            '.eyJmb28iOiJiYXIifQ' +
            '.yMDFowJXjwLXdUm5wTgBSP9nrc4SPCNlYghqjPZdVSYLE112S8S_xIuA3ISTykaCg1kIs2LED0I0lCRMRdqH4g';

        final jwt = JWT.tryVerify(token, hsKey);

        expect(jwt, isNotNull);
        expect(jwt?.payload, equals({'foo': 'bar'}));
      });
    });

    //-------------------//
    // RSASSA-PKCS1-v1_5 //
    //-------------------//
    group('RSASSA-PKCS1-v1_5', () {
      test('.verify RS256', () {
        final token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' +
            '.eyJmb28iOiJiYXIifQ' +
            '.YHSMCF3EegI4GLg46jfD7HBEbqq7qgQ-wOlAnepxxe7Mewtrw3hvfM4bxAi70UqzNdCl3tIqvlATlTyG7VZf9tjb1PG9TGyEaqz87rJktsq0hUbZxKRZgbADHxKjUk_QVuwF39XYv4_ENYVUNDXU5nQJ_d1W2JW-1SzI3cwn_qRqyryyL_x6TOQbtbWdxusJBL-uJmE2XZMqGJah3ZrWICh_ehswwDfZXCifUfHYOnLlzoDuqzeYyoi1y_l83wIBaopF2lbopgjAdZGzrP2kUsDm2RlcGNAlGKGoV3W7rGuosGNsBDHkHYuIFwoPti77bcbticv2nBn1ksGmxvYxiw';

        final jwt = JWT.tryVerify(token, rsaPubKey);

        expect(jwt, isNotNull);
        expect(jwt?.payload, equals({'foo': 'bar'}));
      });
      test('.verify RS384', () {
        final token = 'eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9' +
            '.eyJmb28iOiJiYXIifQ' +
            '.JdaVcZhrmwThENssjjFxL8nTovqCmAmDKl81jU1pBpKRShokN_KPasMhxrwgKQQVubQP3a_GV8JMdz_VRikoMm_iFhj8OUXIt74eZhuZXD6CaZrRrHCBWNX0FfT0OnwjtkNiHsza2dne8WZ4nf1M1g9vOZ4JF2cQ7DfwX6SPuV_nhzkuBcYAifjNYUbFUeKQFRVhoXAnrvvBFT2wCa5pa1QrFpsZbPEsOclCAIwLUx7sbA7V8jZWLDXQm0rlsTUEDAG0g8PQArXf8MiKmOFkoxNPMgmgdt0H6Ju1KqYdmgsTJ87TadLBQ7PVCTm6GfCtSSZBMHfWmvectVWYGRjiHQ';

        final jwt = JWT.tryVerify(token, rsaPubKey);

        expect(jwt, isNotNull);
        expect(jwt?.payload, equals({'foo': 'bar'}));
      });
      test('.verify RS512', () {
        final token = 'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9' +
            '.eyJmb28iOiJiYXIifQ' +
            '.pIqXt4HVhvjNS-6mPEz9mR7pr8V-w1u-x1jMN7Tie-eqLUEcYA6I-3SeSHfCfEDhM4ssp7wpPZ4CoFJV3m_hQR-sugBbZ6CvSNlGT7U2DXBvmTyHSU-eckM7y4fxWGsa8-PIm1MZHKvIUCD5vYcXKgt0mz_57OOXikcT-sgbUDYB0HU0Gii_klO7QNUV7Wykyu1HK6wg9nQJXJ8rzFhPMGR3Nqo-D9UIhayl714Tm-ZqdAWRD1YMsK6zJz5ajQu1_NZ11j4ACAVF2BuzSSfT2Cuw1zMcE_7xce1nSt1sHho__SBobsUPvO_Izp12ppz--zcAC6dPS1_4W8GxuiodEQ';

        final jwt = JWT.tryVerify(token, rsaPubKey);

        expect(jwt, isNotNull);
        expect(jwt?.payload, equals({'foo': 'bar'}));
      });
    });

    //-------//
    // ECDSA //
    //-------//
    group('ECDSA', () {
      test('.verify ES256', () {
        final token = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9' +
            '.eyJmb28iOiJiYXIifQ' +
            '.mUJVRsRm7VXpxNHfVWdU43BJtuV8MKDcNMSr9agp_-M4FsamUibn04y8PgNzQizdw9BWTwkjQcpm1Go1LHPMyg';

        final jwt = JWT.tryVerify(token, ecPubKey);

        expect(jwt, isNotNull);
        expect(jwt?.payload, equals({'foo': 'bar'}));
      });
      test('.verify ES256K', () {
        final token = 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ' +
            '.eyJmb28iOiJiYXIifQ' +
            '.ZuwDjYNGu7PLS_knFAASC_J4t4tcmv6PHV7Pm_QJImqoCs0K96WFVCDchW4gy6AFE4ANAGTOGgfPcQFulNDAFQ';

        final jwt = JWT.tryVerify(token, secp256kPubKey);

        expect(jwt, isNotNull);
        expect(jwt?.payload, equals({'foo': 'bar'}));
      });
      test('.verify ES384', () {
        final token = 'eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9' +
            '.eyJmb28iOiJiYXIifQ' +
            '.c0CieEtA25lXmmX3VLeBy0ir8Gv41QGHiwwfHCfzied3v3Ur3DOP0PVjvBkSXQy82iYAWBfjDBj44ZBpwqE4DA';

        final jwt = JWT.tryVerify(token, ecPubKey);

        expect(jwt, isNotNull);
        expect(jwt?.payload, equals({'foo': 'bar'}));
      });
      test('.verify ES512', () {
        final token = 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9' +
            '.eyJmb28iOiJiYXIifQ' +
            '.WwnWqtru-JEM1fvkYFEgm5946iSk1esdZuBNbQAbfdg6FURD-3J6HEEoLlIQQ8oh8LfdyDR8KSAVt83WLHUFqg';

        final jwt = JWT.tryVerify(token, ecPubKey);

        expect(jwt, isNotNull);
        expect(jwt?.payload, equals({'foo': 'bar'}));
      });
    });

    //------------//
    // RSASSA-PSS //
    //------------//
    group('RSASSA-PSS', () {
      test('.verify PS256', () {
        final token = 'eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9' +
            '.eyJmb28iOiJiYXIifQ' +
            '.JYyEew2G-Bb6p8L7BCfZ79o-42HlMynq7zS_Rc_3q3M2CjvaEY1F_ratOPlveR8wqTAN6swxVfx48ZdRnV282EckX9JOel_MjQH87Iutauj-v6D90xLW2IZt-T2gOkqIo2AQ2i1PeM47jCwbawwuYyy_G433-Rw3tP2j6neNV9tTIAjQicaDVxeqKcvF3l1YjsSLqrLGB4rHLZcCv47CURpO9ZB7WgmOvP_vqKJB_Pcoo6iMI0EIW6REYFIXF1Wxs8Xg9Schyb6p1WjRD4fGPDW9m_uqoaOw9TfAh4GKeWYXE5sw1EZH2l5grStK3_dA0bLeLCOKZkZJZm-TD_cyRw';

        final jwt = JWT.tryVerify(token, rsaPubKey);

        expect(jwt, isNotNull);
        expect(jwt?.payload, equals({'foo': 'bar'}));
      });
      test('.verify PS384', () {
        final token = 'eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9' +
            '.eyJmb28iOiJiYXIifQ' +
            '.dsTJLDMHPG39hBvTWrRAaSFJjRZ8oy5mTPi4EXfgzHj95UznA_LTJwS_T_BCPZ0nU3xjdybyFo7KQU07npShBt4h-1_qsD_VtHZpRFNrzLj9M2mJ40AdQGr_br4itcTotjycy3D6OCCbibHll4zokklRqdz5GL1ofqlMV4a07UzaaDngMXtd88rRclPYR2Z6tW9B_YLqQa_zIRm2kjt2_UuyC2vS70NpbtCWGnB07xLWfTvTLeTwTMfmWcemTEmIq6c-yLSdhenvhJbnKaIDYp7XLqvQPg-cJItAefE-K0aOB1-dji_VLL1GDn1wdkqMaou3ZJ3c8-iSW1uxmW7XSA';

        final jwt = JWT.tryVerify(token, rsaPubKey);

        expect(jwt, isNotNull);
        expect(jwt?.payload, equals({'foo': 'bar'}));
      });
      test('.verify PS512', () {
        final token = 'eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9' +
            '.eyJmb28iOiJiYXIifQ' +
            '.qxSGiQw_OxrmC5AXJB8-06BFjSUyzZv8qK6ClvFHYAh57RrDHBcX-Msly0woDYgxc4ZMTnqJcncbDkA6caXil6e-3q5HPbcjU__tHaCWVglfM9A0ckObE_LL_Q6eJd7aYUFRCvgJ1bmjnT8KUmIMs5dM0PIlAgcVDiBdHkrEa4i8cdl9wd0W3xVOrbSuXc3NVAt5kSHdrC7dK5Zmx6aYmrbD346W_Kg-JmZwJwUzq8BPlbOaRbIg1OkkEtGV2SvI552zbcR0dR_1tB26cIn7G2CIKN77qULVRwZHpzZbM9HzL5edu4U8OzijyRfA1bWLfPNEgy0VYw6zskzReFRCiA';

        final jwt = JWT.tryVerify(token, rsaPubKey);

        expect(jwt, isNotNull);
        expect(jwt?.payload, equals({'foo': 'bar'}));
      });
    });

    //-------//
    // EdDSA //
    //-------//
    group('EdDSA', () {
      test('.verify EdDSA', () {
        final token = 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9' +
            '.eyJmb28iOiJiYXIifQ' +
            '.6Bw5vvdpJ_kgDwidU1l7aagtKCD9-QIJxrz44HXxtc6OJoOmImNko0dgXYpTtXhcEuX7vamSR5JPfGP1Q9d9DA';

        final jwt = JWT.tryVerify(token, edPubKey);

        expect(jwt, isNotNull);
        expect(jwt?.payload, equals({'foo': 'bar'}));
      });
    });
  });
}
