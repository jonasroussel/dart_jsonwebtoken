import 'dart:convert';

final jsonBase64 = json.fuse(utf8.fuse(base64Url));

String base64Unpadded(String value) {
  if (value.endsWith('==')) return value.substring(0, value.length - 2);
  if (value.endsWith('=')) return value.substring(0, value.length - 1);
  return value;
}

String base64Padded(String value) {
  final lenght = value.length;

  switch (lenght % 4) {
    case 2:
      return value.padRight(lenght + 2, '=');
    case 3:
      return value.padRight(lenght + 1, '=');
    default:
      return value;
  }
}

int secondsSinceEpoch(DateTime time) {
  return time.millisecondsSinceEpoch ~/ 1000;
}
