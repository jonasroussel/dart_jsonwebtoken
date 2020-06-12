abstract class Key {}

class SecretKey extends Key {
  String key;

  SecretKey(this.key);
}

class PrivateKey extends Key {
  String key;
  String passphrase;

  PrivateKey(this.key, [this.passphrase = '']);
}

class PublicKey extends Key {
  String key;
  String passphrase;

  PublicKey(this.key, [this.passphrase = '']);
}
