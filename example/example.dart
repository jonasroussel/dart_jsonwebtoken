import 'package:jsonwebtoken/jsonwebtoken.dart';

main() {
  final token = JWT(
    payload: {
      'hello': 'world',
    },
  ).sign(key: 'test');

  print(token);
}
