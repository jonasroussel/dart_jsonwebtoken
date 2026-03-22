// Ed25519 sign/verify/publicKeyFromSeed — vendored from the `cryptography`
// package v2.9.0 (Apache 2.0, Copyright 2019-2020 Gohilla) and adapted to use
// pointycastle's synchronous SHA-512.
//
// Source files:
//   lib/src/dart/ed25519_impl.dart  (Register25519, Ed25519Point, RegisterL)
//   lib/src/dart/x25519_impl.dart   (mod38Mul)
//   lib/src/dart/ed25519.dart        (DartEd25519 point math & sign/verify)
//   lib/src/_internal/big_int.dart   (bigIntFromBytes, bigIntToBytes)

import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart' as pc;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Signs [message] with the 32-byte Ed25519 [seed].
/// Returns a 64-byte signature.
Uint8List ed25519Sign(Uint8List seed, Uint8List message) {
  assert(seed.length == 32);

  // Hash the seed.
  final privateKeyHash = _sha512(seed);
  final clamped = Uint8List.fromList(privateKeyHash.sublist(0, 32));
  _clampPrivateKey(clamped);

  // Derive public key.
  final publicKeyBytes = _pointCompress(
    _pointMul(Register25519()..setBytes(clamped), Ed25519Point.base),
  );

  // r = SHA-512(privateKeyHash[32..] || message) mod L
  final rHash = _sha512(_join([privateKeyHash.sublist(32), message]));
  final rL = RegisterL()..readBytes(rHash);

  // R = r * B
  final pointR = _pointMul(rL.toRegister25519(), Ed25519Point.base);
  final pointRBytes = _pointCompress(pointR);

  // s = SHA-512(R || publicKey || message) mod L
  final sHash = _sha512(_join([pointRBytes, publicKeyBytes, message]));
  final s = RegisterL()..readBytes(sHash);

  // S = (s * a + r) mod L
  s.mul(s, RegisterL()..readBytes(clamped));
  s.add(s, rL);

  return Uint8List.fromList([...pointRBytes, ...s.toBytes()]);
}

/// Verifies an Ed25519 [signature] (64 bytes) of [message] against a 32-byte
/// [publicKeyBytes].
bool ed25519Verify(
  Uint8List publicKeyBytes,
  Uint8List message,
  Uint8List signature,
) {
  if (publicKeyBytes.length != 32) return false;
  if (signature.length != 64) return false;
  if (signature[63] & 0xE0 != 0) return false;

  final a = _pointDecompress(publicKeyBytes);
  if (a == null) return false;

  final rBytes = signature.sublist(0, 32);
  final r = _pointDecompress(rBytes);
  if (r == null) return false;

  final s = _bigIntFromBytesLE(signature.sublist(32));
  if (s >= RegisterL.constantL) return false;

  final hHash = _sha512(_join([rBytes, publicKeyBytes, message]));
  final h = RegisterL()..readBytes(hHash);

  // s * B
  final sB = _pointMul(Register25519()..setBigInt(s), Ed25519Point.base);

  // h * A + R
  final hA = _pointMul(h.toRegister25519(), a);
  final rhA = Ed25519Point.zero();
  _pointAdd(rhA, hA, r);

  return sB.equals(rhA);
}

/// Derives the 32-byte Ed25519 public key from a 32-byte [seed].
Uint8List ed25519PublicKeyFromSeed(Uint8List seed) {
  assert(seed.length == 32);
  final hash = _sha512(seed);
  final clamped = Uint8List.fromList(hash.sublist(0, 32));
  _clampPrivateKey(clamped);
  return _pointCompress(
    _pointMul(Register25519()..setBytes(clamped), Ed25519Point.base),
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

Uint8List _sha512(Uint8List data) => pc.Digest('SHA-512').process(data);

void _clampPrivateKey(List<int> list) {
  list[0] &= 0xF8;
  list[31] &= 0x7F;
  list[31] |= 0x40;
}

Uint8List _join(List<List<int>> parts) {
  final buf = Uint8List(parts.fold<int>(0, (a, b) => a + b.length));
  var i = 0;
  for (var part in parts) {
    buf.setAll(i, part);
    i += part.length;
  }
  return buf;
}

// ---------------------------------------------------------------------------
// Little-endian BigInt conversions (used by RegisterL)
// ---------------------------------------------------------------------------

final _byteMask = BigInt.from(255);

BigInt _bigIntFromBytesLE(List<int> bytes) {
  var result = BigInt.zero;
  for (var i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8) + BigInt.from(bytes[i]);
  }
  return result;
}

Uint8List _bigIntToBytesLE(BigInt? value, Uint8List result) {
  for (var i = 0; i < result.length; i++) {
    result[i] = (_byteMask & value!).toInt();
    value >>= 8;
  }
  return result;
}

// ---------------------------------------------------------------------------
// Ed25519 point operations (from cryptography package)
// ---------------------------------------------------------------------------

Uint8List _pointCompress(Ed25519Point p) {
  final zInv = Register25519();
  final x = Register25519();
  final y = Register25519();

  zInv.pow(p.z, Register25519.pMinusTwo);
  x.mul(p.x, zInv);
  y.mul(p.y, zInv);

  assert(0x8000 & y.data[15] == 0);
  y.data[15] |= (0x1 & x.data[0]) << 15;

  return y.toBytes(Uint8List(32));
}

Ed25519Point? _pointDecompress(List<int> pointBytes) {
  assert(pointBytes.length == 32);
  final s = Uint8List.fromList(pointBytes);
  final sign = (0x80 & s[31]) >> 7;
  s[31] &= 0x7F;

  final y = Register25519()..setBytes(s);

  if (y.isGreaterOrEqual(Register25519.P)) return null;

  final v0 = Register25519();
  final v1 = Register25519();

  v0.mul(y, y);
  v0.sub(v0, Register25519.one);

  v1.mul(y, y);
  v1.mul(v1, Register25519.D);
  v1.add(v1, Register25519.one);
  v1.pow(v1, Register25519.pMinusTwo);

  final x2 = Register25519()..mul(v0, v1);

  if (x2.isZero) {
    if (sign == 1) return null;
    return Ed25519Point(
      Register25519.zero,
      y,
      Register25519.one,
      Register25519.zero,
    );
  }

  final x = v0;
  x.setBigInt(Register25519.pPlus3Slash8.toBigInt());
  x.pow(x2, x);

  v1.mul(x, x);
  v1.sub(v1, x2);
  if (!v1.isZero) x.mul(x, Register25519.Z);

  v1.mul(x, x);
  v1.sub(v1, x2);
  if (!v1.isZero) return null;

  if ((0x1 & x.data[0]) != sign) x.sub(Register25519.P, x);

  final xy = v1;
  xy.mul(x, y);

  return Ed25519Point(x, y, Register25519.one, xy);
}

void _pointAdd(Ed25519Point r, Ed25519Point p, Ed25519Point q,
    {Ed25519Point? tmp}) {
  tmp ??= Ed25519Point.zero();
  final a = r.x, b = r.y, c = r.z, d = r.w;
  final e = tmp.x, f = tmp.y, g = tmp.z, h = tmp.w;

  a.sub(p.y, p.x);
  b.sub(q.y, q.x);
  a.mul(a, b);

  b.add(p.y, p.x);
  c.add(q.y, q.x);
  b.mul(b, c);

  c.mul(Register25519.two, p.w);
  c.mul(c, q.w);
  c.mul(c, Register25519.D);

  d.mul(Register25519.two, p.z);
  d.mul(d, q.z);

  e.sub(b, a);
  f.sub(d, c);
  g.add(d, c);
  h.add(b, a);

  a.mul(e, f);
  b.mul(g, h);
  c.mul(f, g);
  d.mul(e, h);
}

Ed25519Point _pointMul(Register25519 s, Ed25519Point pointP) {
  var q = Ed25519Point.zero();
  q.y.data[0] = 1;
  q.z.data[0] = 1;

  pointP = Ed25519Point(
    Register25519.from(pointP.x),
    Register25519.from(pointP.y),
    Register25519.from(pointP.z),
    Register25519.from(pointP.w),
  );

  var tmp0 = Ed25519Point.zero();
  final tmp1 = Ed25519Point.zero();

  for (var i = 0; i < 256; i++) {
    final b = 0x1 & (s.data[i ~/ 16] >> (i % 16));
    if (b == 1) {
      _pointAdd(tmp0, q, pointP, tmp: tmp1);
      final oldQ = q;
      q = tmp0;
      tmp0 = oldQ;
    }
    _pointAdd(tmp0, pointP, pointP, tmp: tmp1);
    final oldP = pointP;
    pointP = tmp0;
    tmp0 = oldP;
  }
  return q;
}

// ---------------------------------------------------------------------------
// Ed25519Point
// ---------------------------------------------------------------------------

final _mask16 = BigInt.from(0xFFFF);

class Ed25519Point {
  static final base = () {
    final y = Register25519()
      ..parse(
        '46316835694926478169428394003475163141307993866256225615783033603165251855960',
      );
    final x = Register25519()
      ..parse(
        '15112221349535400772501151409588531511454012693041857206046113283949847762202',
      );
    final xy = Register25519()..mul(x, y);
    return Ed25519Point(x, y, Register25519.one, xy);
  }();

  final Register25519 x, y, z, w;

  Ed25519Point(this.x, this.y, this.z, this.w);

  Ed25519Point.zero()
      : this(
          Register25519(),
          Register25519(),
          Register25519(),
          Register25519(),
        );

  bool equals(Ed25519Point other) {
    final v0 = Register25519();
    final v1 = Register25519();

    v0.mul(x, other.z);
    v1.mul(z, other.x);
    v0.sub(v0, v1);
    if (!v0.isZero) return false;

    v0.mul(y, other.z);
    v1.mul(z, other.y);
    v0.sub(v0, v1);
    return v0.isZero;
  }
}

// ---------------------------------------------------------------------------
// Register25519 — field element mod 2^255-19, stored as 16 x uint16 (LE)
// ---------------------------------------------------------------------------

class Register25519 {
  static final Register25519 zero = Register25519()..data[0] = 0;
  static final Register25519 one = Register25519()..data[0] = 1;
  static final Register25519 two = Register25519()..data[0] = 2;

  static final Z = Register25519()
    ..parse(
      '19681161376707505956807079304988542015446066515923890162744021073123829784752',
    );

  static final D = Register25519()
    ..parse(
      '37095705934669439343138083508754565189542113879843219016388785533085940283555',
    );

  static final pPlus3Slash8 = Register25519()
    ..data[0] = 0xFFFE
    ..data.fillRange(1, 15, 0xFFFF)
    ..data[15] = 0x0FFF;

  static final Register25519 P = Register25519()
    ..data[0] = 0xFFED
    ..data.fillRange(1, 15, 0xFFFF)
    ..data[15] = 0x7FFF;

  static final pMinusTwo = Register25519()
    ..data.setAll(0, P.data)
    ..data[0] -= 2;

  static final _p = BigInt.two.pow(255) - BigInt.from(19);

  final Int32List data;

  Register25519([Int32List? data]) : data = data ?? Int32List(16);

  factory Register25519.from(Register25519 r) {
    return Register25519(Int32List.fromList(r.data));
  }

  bool get isZero => data.every((e) => e == 0);

  void add(Register25519 a, Register25519 b) {
    final ad = a.data, bd = b.data, cd = data;
    var last = 0;
    for (var i = 0; i < 16; i++) {
      last = ad[i] + bd[i] + (last ~/ 0x10000);
      cd[i] = 0xFFFF & last;
    }
    cd[15] += (last ~/ 0x10000) * 0x10000;
    _mod19();
  }

  bool isGreaterOrEqual(Register25519 other) {
    final a = data, b = other.data;
    for (var i = 15; i >= 0; i--) {
      if (a[i] < b[i]) return false;
      if (a[i] > b[i]) return true;
    }
    return true;
  }

  void mul(Register25519 a, Register25519 b) {
    _mod38Mul(data, a.data, b.data);
    _mod19();
  }

  void parse(String s) => setBigInt(BigInt.parse(s));

  void pow(Register25519 base, Register25519 exponent) {
    setBigInt(base.toBigInt().modPow(exponent.toBigInt(), _p));
  }

  void set(Register25519 a) => data.setAll(0, a.data);

  void setBigInt(BigInt bigInt) {
    for (var i = 0; i < 16; i++) {
      data[i] = (_mask16 & bigInt).toInt();
      bigInt >>= 16;
    }
  }

  void setBytes(Uint8List packed) {
    final byteData = ByteData.view(packed.buffer, packed.offsetInBytes, 32);
    for (var i = 0; i < 16; i++) {
      data[i] = byteData.getUint16(2 * i, Endian.little);
    }
  }

  void sub(Register25519 a, Register25519 b) {
    final ad = a.data, bd = b.data, cd = data, pd = P.data;
    var last = 0;
    for (var i = 0; i < 16; i++) {
      last = pd[i] + pd[i] + ad[i] - bd[i] + (last >> 16);
      cd[i] = 0xFFFF & last;
    }
    cd[15] |= (last >> 16) << 16;
    _mod19();
  }

  BigInt toBigInt() {
    var result = BigInt.zero;
    for (var i = 0; i < 16; i++) {
      result |= (BigInt.from(data[i]) << (i * 16));
    }
    return result;
  }

  Uint8List toBytes([Uint8List? result]) {
    result ??= Uint8List(32);
    final byteData = ByteData.view(result.buffer, result.offsetInBytes, 32);
    for (var i = 0; i < 16; i++) {
      byteData.setUint16(2 * i, 0xFFFF & data[i], Endian.little);
    }
    return result;
  }

  void _mod19() {
    while (isGreaterOrEqual(P)) {
      final a = data;
      var previous = a[0] - 0xFFED;
      a[0] = 0xFFFF & previous;
      for (var i = 1; i < 15; i++) {
        final current = a[i] - 0xFFFF - (1 & (previous >> 16));
        a[i] = 0xFFFF & current;
        previous = current;
      }
      a[15] = a[15] - 0x7FFF - (1 & (previous >> 16));
    }
  }
}

// ---------------------------------------------------------------------------
// RegisterL — arithmetic mod the group order L
// ---------------------------------------------------------------------------

class RegisterL {
  static final constantL = BigInt.parse(
    '7237005577332262213973186563042994240857116359379907606001950938285454250989',
  );

  BigInt? _value;

  void add(RegisterL a, RegisterL b) {
    _value = (a.toBigInt()! + b.toBigInt()!) % constantL;
  }

  void mul(RegisterL a, RegisterL b) {
    _value = (a.toBigInt()! * b.toBigInt()!) % constantL;
  }

  void readBytes(List<int> bytes) {
    _value = _bigIntFromBytesLE(bytes) % constantL;
  }

  BigInt? toBigInt() => _value;

  Uint8List toBytes() => _bigIntToBytesLE(_value, Uint8List(32));

  Register25519 toRegister25519() => Register25519()..setBigInt(toBigInt()!);
}

// ---------------------------------------------------------------------------
// mod38Mul — (a * b) mod (2^256 - 38)  (from x25519_impl.dart)
// ---------------------------------------------------------------------------

void _mod38Mul(Int32List result, Int32List a, Int32List b) {
  var t0 = 0,
      t1 = 0,
      t2 = 0,
      t3 = 0,
      t4 = 0,
      t5 = 0,
      t6 = 0,
      t7 = 0,
      t8 = 0,
      t9 = 0,
      t10 = 0,
      t11 = 0,
      t12 = 0,
      t13 = 0,
      t14 = 0,
      t15 = 0,
      t16 = 0,
      t17 = 0,
      t18 = 0,
      t19 = 0,
      t20 = 0,
      t21 = 0,
      t22 = 0,
      t23 = 0,
      t24 = 0,
      t25 = 0,
      t26 = 0,
      t27 = 0,
      t28 = 0,
      t29 = 0,
      t30 = 0,
      b0 = b[0],
      b1 = b[1],
      b2 = b[2],
      b3 = b[3],
      b4 = b[4],
      b5 = b[5],
      b6 = b[6],
      b7 = b[7],
      b8 = b[8],
      b9 = b[9],
      b10 = b[10],
      b11 = b[11],
      b12 = b[12],
      b13 = b[13],
      b14 = b[14],
      b15 = b[15];

  var v = a[0];
  t0 += v * b0;
  t1 += v * b1;
  t2 += v * b2;
  t3 += v * b3;
  t4 += v * b4;
  t5 += v * b5;
  t6 += v * b6;
  t7 += v * b7;
  t8 += v * b8;
  t9 += v * b9;
  t10 += v * b10;
  t11 += v * b11;
  t12 += v * b12;
  t13 += v * b13;
  t14 += v * b14;
  t15 += v * b15;
  v = a[1];
  t1 += v * b0;
  t2 += v * b1;
  t3 += v * b2;
  t4 += v * b3;
  t5 += v * b4;
  t6 += v * b5;
  t7 += v * b6;
  t8 += v * b7;
  t9 += v * b8;
  t10 += v * b9;
  t11 += v * b10;
  t12 += v * b11;
  t13 += v * b12;
  t14 += v * b13;
  t15 += v * b14;
  t16 += v * b15;
  v = a[2];
  t2 += v * b0;
  t3 += v * b1;
  t4 += v * b2;
  t5 += v * b3;
  t6 += v * b4;
  t7 += v * b5;
  t8 += v * b6;
  t9 += v * b7;
  t10 += v * b8;
  t11 += v * b9;
  t12 += v * b10;
  t13 += v * b11;
  t14 += v * b12;
  t15 += v * b13;
  t16 += v * b14;
  t17 += v * b15;
  v = a[3];
  t3 += v * b0;
  t4 += v * b1;
  t5 += v * b2;
  t6 += v * b3;
  t7 += v * b4;
  t8 += v * b5;
  t9 += v * b6;
  t10 += v * b7;
  t11 += v * b8;
  t12 += v * b9;
  t13 += v * b10;
  t14 += v * b11;
  t15 += v * b12;
  t16 += v * b13;
  t17 += v * b14;
  t18 += v * b15;
  v = a[4];
  t4 += v * b0;
  t5 += v * b1;
  t6 += v * b2;
  t7 += v * b3;
  t8 += v * b4;
  t9 += v * b5;
  t10 += v * b6;
  t11 += v * b7;
  t12 += v * b8;
  t13 += v * b9;
  t14 += v * b10;
  t15 += v * b11;
  t16 += v * b12;
  t17 += v * b13;
  t18 += v * b14;
  t19 += v * b15;
  v = a[5];
  t5 += v * b0;
  t6 += v * b1;
  t7 += v * b2;
  t8 += v * b3;
  t9 += v * b4;
  t10 += v * b5;
  t11 += v * b6;
  t12 += v * b7;
  t13 += v * b8;
  t14 += v * b9;
  t15 += v * b10;
  t16 += v * b11;
  t17 += v * b12;
  t18 += v * b13;
  t19 += v * b14;
  t20 += v * b15;
  v = a[6];
  t6 += v * b0;
  t7 += v * b1;
  t8 += v * b2;
  t9 += v * b3;
  t10 += v * b4;
  t11 += v * b5;
  t12 += v * b6;
  t13 += v * b7;
  t14 += v * b8;
  t15 += v * b9;
  t16 += v * b10;
  t17 += v * b11;
  t18 += v * b12;
  t19 += v * b13;
  t20 += v * b14;
  t21 += v * b15;
  v = a[7];
  t7 += v * b0;
  t8 += v * b1;
  t9 += v * b2;
  t10 += v * b3;
  t11 += v * b4;
  t12 += v * b5;
  t13 += v * b6;
  t14 += v * b7;
  t15 += v * b8;
  t16 += v * b9;
  t17 += v * b10;
  t18 += v * b11;
  t19 += v * b12;
  t20 += v * b13;
  t21 += v * b14;
  t22 += v * b15;
  v = a[8];
  t8 += v * b0;
  t9 += v * b1;
  t10 += v * b2;
  t11 += v * b3;
  t12 += v * b4;
  t13 += v * b5;
  t14 += v * b6;
  t15 += v * b7;
  t16 += v * b8;
  t17 += v * b9;
  t18 += v * b10;
  t19 += v * b11;
  t20 += v * b12;
  t21 += v * b13;
  t22 += v * b14;
  t23 += v * b15;
  v = a[9];
  t9 += v * b0;
  t10 += v * b1;
  t11 += v * b2;
  t12 += v * b3;
  t13 += v * b4;
  t14 += v * b5;
  t15 += v * b6;
  t16 += v * b7;
  t17 += v * b8;
  t18 += v * b9;
  t19 += v * b10;
  t20 += v * b11;
  t21 += v * b12;
  t22 += v * b13;
  t23 += v * b14;
  t24 += v * b15;
  v = a[10];
  t10 += v * b0;
  t11 += v * b1;
  t12 += v * b2;
  t13 += v * b3;
  t14 += v * b4;
  t15 += v * b5;
  t16 += v * b6;
  t17 += v * b7;
  t18 += v * b8;
  t19 += v * b9;
  t20 += v * b10;
  t21 += v * b11;
  t22 += v * b12;
  t23 += v * b13;
  t24 += v * b14;
  t25 += v * b15;
  v = a[11];
  t11 += v * b0;
  t12 += v * b1;
  t13 += v * b2;
  t14 += v * b3;
  t15 += v * b4;
  t16 += v * b5;
  t17 += v * b6;
  t18 += v * b7;
  t19 += v * b8;
  t20 += v * b9;
  t21 += v * b10;
  t22 += v * b11;
  t23 += v * b12;
  t24 += v * b13;
  t25 += v * b14;
  t26 += v * b15;
  v = a[12];
  t12 += v * b0;
  t13 += v * b1;
  t14 += v * b2;
  t15 += v * b3;
  t16 += v * b4;
  t17 += v * b5;
  t18 += v * b6;
  t19 += v * b7;
  t20 += v * b8;
  t21 += v * b9;
  t22 += v * b10;
  t23 += v * b11;
  t24 += v * b12;
  t25 += v * b13;
  t26 += v * b14;
  t27 += v * b15;
  v = a[13];
  t13 += v * b0;
  t14 += v * b1;
  t15 += v * b2;
  t16 += v * b3;
  t17 += v * b4;
  t18 += v * b5;
  t19 += v * b6;
  t20 += v * b7;
  t21 += v * b8;
  t22 += v * b9;
  t23 += v * b10;
  t24 += v * b11;
  t25 += v * b12;
  t26 += v * b13;
  t27 += v * b14;
  t28 += v * b15;
  v = a[14];
  t14 += v * b0;
  t15 += v * b1;
  t16 += v * b2;
  t17 += v * b3;
  t18 += v * b4;
  t19 += v * b5;
  t20 += v * b6;
  t21 += v * b7;
  t22 += v * b8;
  t23 += v * b9;
  t24 += v * b10;
  t25 += v * b11;
  t26 += v * b12;
  t27 += v * b13;
  t28 += v * b14;
  t29 += v * b15;
  v = a[15];
  t15 += v * b0;
  t16 += v * b1;
  t17 += v * b2;
  t18 += v * b3;
  t19 += v * b4;
  t20 += v * b5;
  t21 += v * b6;
  t22 += v * b7;
  t23 += v * b8;
  t24 += v * b9;
  t25 += v * b10;
  t26 += v * b11;
  t27 += v * b12;
  t28 += v * b13;
  t29 += v * b14;
  t30 += v * b15;

  t0 += 38 * t16;
  t1 += 38 * t17;
  t2 += 38 * t18;
  t3 += 38 * t19;
  t4 += 38 * t20;
  t5 += 38 * t21;
  t6 += 38 * t22;
  t7 += 38 * t23;
  t8 += 38 * t24;
  t9 += 38 * t25;
  t10 += 38 * t26;
  t11 += 38 * t27;
  t12 += 38 * t28;
  t13 += 38 * t29;
  t14 += 38 * t30;

  var c = 1;
  v = t0 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t0 = v - c * 0x10000;
  v = t1 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t1 = v - c * 0x10000;
  v = t2 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t2 = v - c * 0x10000;
  v = t3 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t3 = v - c * 0x10000;
  v = t4 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t4 = v - c * 0x10000;
  v = t5 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t5 = v - c * 0x10000;
  v = t6 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t6 = v - c * 0x10000;
  v = t7 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t7 = v - c * 0x10000;
  v = t8 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t8 = v - c * 0x10000;
  v = t9 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t9 = v - c * 0x10000;
  v = t10 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t10 = v - c * 0x10000;
  v = t11 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t11 = v - c * 0x10000;
  v = t12 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t12 = v - c * 0x10000;
  v = t13 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t13 = v - c * 0x10000;
  v = t14 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t14 = v - c * 0x10000;
  v = t15 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t15 = v - c * 0x10000;
  t0 += 38 * (c - 1);

  c = 1;
  v = t0 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t0 = v - c * 0x10000;
  v = t1 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t1 = v - c * 0x10000;
  v = t2 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t2 = v - c * 0x10000;
  v = t3 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t3 = v - c * 0x10000;
  v = t4 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t4 = v - c * 0x10000;
  v = t5 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t5 = v - c * 0x10000;
  v = t6 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t6 = v - c * 0x10000;
  v = t7 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t7 = v - c * 0x10000;
  v = t8 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t8 = v - c * 0x10000;
  v = t9 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t9 = v - c * 0x10000;
  v = t10 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t10 = v - c * 0x10000;
  v = t11 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t11 = v - c * 0x10000;
  v = t12 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t12 = v - c * 0x10000;
  v = t13 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t13 = v - c * 0x10000;
  v = t14 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t14 = v - c * 0x10000;
  v = t15 + c + 0xFFFF;
  c = v ~/ 0x10000;
  t15 = v - c * 0x10000;
  t0 += 38 * (c - 1);

  result[0] = t0;
  result[1] = t1;
  result[2] = t2;
  result[3] = t3;
  result[4] = t4;
  result[5] = t5;
  result[6] = t6;
  result[7] = t7;
  result[8] = t8;
  result[9] = t9;
  result[10] = t10;
  result[11] = t11;
  result[12] = t12;
  result[13] = t13;
  result[14] = t14;
  result[15] = t15;
}
