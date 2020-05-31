class JWTError extends Error {
  JWTError(this.message);

  final String message;
}

class JWTInvalidError extends JWTError {
  JWTInvalidError(String message) : super(message);
}

class JWTExpiredError extends JWTError {
  JWTExpiredError() : super('jwt expired');
}
