import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:test/test.dart';

import 'keys_const.dart';

void main() {
  group('JWTKey', () {
    test('should convert SecretKey to JWK', () {
      final jwk = hsKey.toJWK();

      expect(
        jwk,
        equals({
          'kty': 'oct',
          'use': 'sig',
          'k': 'c2VjcmV0IHBhc3NwaHJhc2U',
        }),
      );

      final jwkWithAlgorithm = hsKey.toJWK(algorithm: JWTAlgorithm.HS256);
      expect(jwkWithAlgorithm['alg'], equals('HS256'));
    });

    test('should convert RSAPrivateKey to JWK', () {
      final jwk = rsaPrivKey.toJWK();

      expect(
        jwk,
        equals({
          'kty': 'RSA',
          'use': 'sig',
          'p':
              '8KNThCO2gsC2I9PQDM_8Cw0O983WCDY-oi-7JPiNAJwv5DYBqEZB1QYdj06YD16XlC_HAZMsMku1na2TN0driwenQQWzoev3g2S7gRDoS_FCJSI3jJ-kjgtaA7Qmzlgk1TxODN-G1H91HW7t0l7VnL27IWyYo2qRRK3jzxqUiPU',
          'q':
              'x0oQs2reBQGMVZnApD1jeq7n4MvNLcPvt8b_eU9iUv6Y4Mj0Suo_AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDUAhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn__LiH1B3rXhcdyo3_vIttEk48RakUKClU8',
          'd':
              'pOaNpLq2QrwGU9cKVNDa-nP83q7EN5LfmZempqyqyRWVoCJ2CD-xaqmNcNtev3ei0gwuVawz5fQKowOBJcp6MtLaPHgYOMjVlNeD77QAwnywnvilbNUM5-YIRD_vBezf5xudeEquI7xnTfqr3ZBzX43ztIjfyeQZrQAEf0I3zceZCq3h8HtR0fO4hF7-Z7Y8aEirlkHOPqHcGmg8bMQ_7HeX1iYry3_Vw3Smoj51DBh2B8aNpyQu7_aofzQwIXsjJBqx5lQ4nIqsIu1IP8iLG_-HMMRQ984KMUOBOnN_dzC1rz6gTjAcKjWIjX_hOU-TCZfHipJe2bDhpA_PsgNC8Q',
          'e': 'AQAB',
          'dp':
              'zV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD_ISLDY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnKxt1Il2HgxOBvbhOT-9in1BzA-YJ99UzC85O0Qz06A-CmtHEy4aZ2kj5hHjE',
          'dq':
              'mNS4-A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2-cwPLhPIzIuwytXywh2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfzet6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEs',
          'qi':
              'JzNw0H9xSaEp12jIa1QSKL4nOZdMRZBB7JAIxU3rzvOhbM9QtmknkSkqhhaDkNLZicwRLNUeiqpxyJ4nA00KyoQK4C11-L9wnXY300SZBVg2xPwpLymTTq3H9Z4Whgj7KUSY9ilJI9RYZfQp3HZ_0bGBDjW8EEoyHzD5L8RfvB0',
          'n':
              'u1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0_IzW7yWR7QkrmBL7jTKEn5u-qKhbwKfBstIs-bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW_VDL5AaWTg0nLVkjRo9z-40RQzuVaE8AkAFmxZzow3x-VJYKdjykkJ0iT9wCS0DRTXu269V264Vf_3jvredZiKRkgwlL9xNAwxXFg0x_XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC-9aGVd-Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmw'
        }),
      );

      final jwkWithAlgorithm = rsaPrivKey.toJWK(algorithm: JWTAlgorithm.RS256);
      expect(jwkWithAlgorithm['alg'], equals('RS256'));
    });

    test("should convert RSAPublicKey to JWK", () {
      final jwk = rsaPubKey.toJWK();

      expect(
        jwk,
        equals({
          'kty': 'RSA',
          'use': 'sig',
          'e': 'AQAB',
          'n':
              'u1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0_IzW7yWR7QkrmBL7jTKEn5u-qKhbwKfBstIs-bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW_VDL5AaWTg0nLVkjRo9z-40RQzuVaE8AkAFmxZzow3x-VJYKdjykkJ0iT9wCS0DRTXu269V264Vf_3jvredZiKRkgwlL9xNAwxXFg0x_XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC-9aGVd-Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmw'
        }),
      );

      final jwkWithAlgorithm = rsaPubKey.toJWK(algorithm: JWTAlgorithm.RS256);
      expect(jwkWithAlgorithm['alg'], equals('RS256'));
    });

    test("should convert ECPrivateKey to JWK", () {
      final jwk = ecPrivKey.toJWK();

      expect(
        jwk,
        equals({
          'kty': 'EC',
          'use': 'sig',
          'crv': 'P-256',
          'd': 'evZzL1gdAFr88hb2OF_2NxApJCzGCEDdfSp6VQO30hw',
          'x': 'EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84',
          'y': 'kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY',
          'alg': 'ES256'
        }),
      );
    });

    test("should convert ECPublicKey to JWK", () {
      final jwk = ecPubKey.toJWK();

      expect(
        jwk,
        equals({
          'kty': 'EC',
          'use': 'sig',
          'crv': 'P-256',
          'x': 'EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84',
          'y': 'kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY',
          'alg': 'ES256'
        }),
      );
    });

    test("should convert EdDSAPrivateKey to JWK", () {
      final jwk = edPrivKey.toJWK();

      expect(
        jwk,
        equals({
          'kty': 'OKP',
          'use': 'sig',
          'crv': 'Ed25519',
          'd': 'JcKMEe-MCuNeq5QjmOjfHlIcjih9kDZrPAnf0gL9By0',
          'x': 'Ei7MNW0Q9T83UA3Rw-8DbspMgqeuxCqa2wXaWS-tHqY',
          'alg': 'EdDSA'
        }),
      );
    });

    test("should convert EdDSAPublicKey to JWK", () {
      final jwk = edPubKey.toJWK();

      expect(
        jwk,
        equals({
          'kty': 'OKP',
          'use': 'sig',
          'crv': 'Ed25519',
          'x': 'Ei7MNW0Q9T83UA3Rw-8DbspMgqeuxCqa2wXaWS-tHqY',
          'alg': 'EdDSA'
        }),
      );
    });
  });
}
