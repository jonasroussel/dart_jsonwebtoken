import 'dart:math';

import 'dart:typed_data';

void arrayCopy(List src, int srcPos, List dest, int destPos, int length) {
  dest.setRange(destPos, length + destPos, src, srcPos);
}

final _defaultSecureRandom = Random.secure();

void fillBytesWithSecureRandomNumbers(Uint8List bytes, {Random? random}) {
  random ??= _defaultSecureRandom;
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = random.nextInt(256);
  }
}
