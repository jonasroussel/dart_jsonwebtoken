import 'package:jsonwebtoken/jsonwebtoken.dart';

main() {
  final jwt = JWT(payload: {
    'hello': 'world',
    'iat': 1590774250,
  });

  final token = jwt.sign(key: 'test');

  print(token);
}
