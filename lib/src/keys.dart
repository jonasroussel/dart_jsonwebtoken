abstract class Key {}

/// For HS256 algorithm
class SecretKey extends Key {
  String key;

  SecretKey(this.key);
}

/// For RS256 algorithm, in sign method
class PrivateKey extends Key {
  String key;
  String passphrase;

  PrivateKey(this.key, [this.passphrase = '']);
}

/// For RS256 algorithm, in verify method
class PublicKey extends Key {
  String key;
  String passphrase;

  PublicKey(this.key, [this.passphrase = '']);
}
