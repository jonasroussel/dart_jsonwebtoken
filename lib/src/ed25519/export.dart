library ed25519;

import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:collection/collection.dart';
import 'package:crypto/crypto.dart';

import 'ed25519.dart';
import 'util.dart';

/// PublicKeySize is the size, in bytes, of public keys as used in this package.
const PublicKeySize = 32;

/// PrivateKeySize is the size, in bytes, of private keys as used in this package.
const PrivateKeySize = 64;

/// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
const SignatureSize = 64;

/// SeedSize is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
const SeedSize = 32;

/// PublicKey is the type of Ed25519 public keys.
class PublicKey {
  List<int> bytes;

  PublicKey(this.bytes);
}

/// PrivateKey is the type of Ed25519 private keys.
class PrivateKey {
  List<int> bytes;

  PrivateKey(this.bytes);
}

/// KeyPair is the type of Ed25519 public/private key pair.
class KeyPair {
  final PrivateKey? privateKey;

  final PublicKey? publicKey;

  KeyPair({this.privateKey, this.publicKey});

  @override
  int get hashCode => publicKey.hashCode;

  @override
  bool operator ==(other) =>
      other is KeyPair &&
      publicKey == other.publicKey &&
      privateKey == other.privateKey;
}

// Public returns the PublicKey corresponding to priv.
PublicKey public(PrivateKey privateKey) {
  var publicKey = privateKey.bytes.sublist(32, 32 + PublicKeySize);
  return PublicKey(publicKey);
}

/// Seed returns the private key seed corresponding to priv. It is provided for
/// interoperability with RFC 8032. RFC 8032's private keys correspond to seeds
/// in this package.
Uint8List seed(PrivateKey privateKey) {
  var seed = privateKey.bytes.sublist(0, SeedSize);
  return seed as Uint8List;
}

/// GenerateKey generates a public/private key pair using entropy from secure random.
KeyPair generateKey() {
  var seed = Uint8List(32);
  fillBytesWithSecureRandomNumbers(seed);
  var privateKey = newKeyFromSeed(seed);
  var publicKey = privateKey.bytes.sublist(32, PrivateKeySize);
  return KeyPair(privateKey: privateKey, publicKey: PublicKey(publicKey));
}

/// NewKeyFromSeed calculates a private key from a seed. It will throw
/// ArgumentError if seed.length is not SeedSize.
/// This function is provided for interoperability with RFC 8032.
/// RFC 8032's private keys correspond to seeds in this package.
PrivateKey newKeyFromSeed(Uint8List seed) {
  if (seed.length != SeedSize) {
    throw ArgumentError('ed25519: bad seed length ${seed.length}');
  }
  var h = sha512.convert(seed);
  var digest = h.bytes.sublist(0, 32);
  digest[0] &= 248;
  digest[31] &= 127;
  digest[31] |= 64;

  var A = ExtendedGroupElement();
  var hBytes = digest.sublist(0);
  GeScalarMultBase(A, hBytes as Uint8List);
  var publicKeyBytes = Uint8List(32);
  A.ToBytes(publicKeyBytes);

  var privateKey = Uint8List(PrivateKeySize);
  arrayCopy(seed, 0, privateKey, 0, 32);
  arrayCopy(publicKeyBytes, 0, privateKey, 32, 32);
  return PrivateKey(privateKey);
}

/// Sign signs the message with privateKey and returns a signature. It will
/// throw ArumentError if privateKey.bytes.length is not PrivateKeySize.
Uint8List sign(PrivateKey privateKey, Uint8List message) {
  if (privateKey.bytes.length != PrivateKeySize) {
    throw ArgumentError(
        'ed25519: bad privateKey length ${privateKey.bytes.length}');
  }
  var h = sha512.convert(privateKey.bytes.sublist(0, 32));
  var digest1 = h.bytes;
  var expandedSecretKey = digest1.sublist(0, 32);
  expandedSecretKey[0] &= 248;
  expandedSecretKey[31] &= 63;
  expandedSecretKey[31] |= 64;

  var output = AccumulatorSink<Digest>();
  var input = sha512.startChunkedConversion(output);
  input.add(digest1.sublist(32));
  input.add(message);
  input.close();
  var messageDigest = output.events.single.bytes;

  var messageDigestReduced = Uint8List(32);
  ScReduce(messageDigestReduced, messageDigest as Uint8List);
  var R = ExtendedGroupElement();
  GeScalarMultBase(R, messageDigestReduced);

  var encodedR = Uint8List(32);
  R.ToBytes(encodedR);

  output = AccumulatorSink<Digest>();
  input = sha512.startChunkedConversion(output);
  input.add(encodedR);
  input.add(privateKey.bytes.sublist(32));
  input.add(message);
  input.close();
  var hramDigest = output.events.single.bytes;
  var hramDigestReduced = Uint8List(32);
  ScReduce(hramDigestReduced, hramDigest as Uint8List);

  var s = Uint8List(32);
  ScMulAdd(s, hramDigestReduced, expandedSecretKey as Uint8List,
      messageDigestReduced);

  var signature = Uint8List(SignatureSize);
  arrayCopy(encodedR, 0, signature, 0, 32);
  arrayCopy(s, 0, signature, 32, 32);

  return signature;
}

/// Verify reports whether sig is a valid signature of message by publicKey. It
/// will throw ArgumentError if publicKey.bytes.length is not PublicKeySize.
bool verify(PublicKey publicKey, Uint8List message, Uint8List sig) {
  if (publicKey.bytes.length != PublicKeySize) {
    throw ArgumentError(
        'ed25519: bad publicKey length ${publicKey.bytes.length}');
  }
  if (sig.length != SignatureSize || sig[63] & 224 != 0) {
    return false;
  }

  var A = ExtendedGroupElement();
  var publicKeyBytes = Uint8List.fromList(publicKey.bytes);
  if (!A.FromBytes(publicKeyBytes)) {
    return false;
  }
  FeNeg(A.X, A.X);
  FeNeg(A.T, A.T);

  var output = AccumulatorSink<Digest>();
  var input = sha512.startChunkedConversion(output);
  input.add(sig.sublist(0, 32));
  input.add(publicKeyBytes);
  input.add(message);
  input.close();
  var digest = output.events.single.bytes;

  var hReduced = Uint8List(32);
  ScReduce(hReduced, digest as Uint8List);

  var R = ProjectiveGroupElement();
  var s = sig.sublist(32);

  if (!ScMinimal(s)) {
    return false;
  }

  GeDoubleScalarMultVartime(R, hReduced, A, s);

  var checkR = Uint8List(32);
  R.ToBytes(checkR);
  return ListEquality().equals(sig.sublist(0, 32), checkR);
}
