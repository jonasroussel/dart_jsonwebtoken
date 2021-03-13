import 'package:pointycastle/pointycastle.dart' as pc;

import 'parser.dart';

abstract class Key {}

/// For HMAC algorithms
class SecretKey extends Key {
  String key;

  SecretKey(this.key);
}

/// For RSA algorithm, in sign method
class RSAPrivateKey extends Key {
  pc.RSAPrivateKey? key;

  RSAPrivateKey(String pem) {
    key = parseRSAPrivateKeyPEM(pem);
  }
}

/// For RSA algorithm, in verify method
class RSAPublicKey extends Key {
  pc.RSAPublicKey? key;

  RSAPublicKey(String pem) {
    key = parseRSAPublicKeyPEM(pem);
  }
}

/// For ECDSA algorithm, in sign method
class ECPrivateKey extends Key {
  pc.ECPrivateKey? key;
  late int size;

  ECPrivateKey(String pem) {
    key = parseECPrivateKeyPEM(pem);
    size = (key!.parameters.curve.fieldSize / 8).round();
  }
}

/// For ECDSA algorithm, in verify method
class ECPublicKey extends Key {
  pc.ECPublicKey? key;

  ECPublicKey(String pem) {
    key = parseECPublicKeyPEM(pem);
  }
}
