class JWTError extends Error {
  JWTError(this.message);

  final String message;

  @override
  String toString() => 'JWTError: $message';
}

/// An error thrown when token is invalid
class JWTInvalidError extends JWTError {
  JWTInvalidError(String message) : super(message);
}

/// An error thrown when token is expired
class JWTExpiredError extends JWTError {
  JWTExpiredError() : super('jwt expired');
}

/// An error thrown when token is not active
class JWTNotActiveError extends JWTError {
  JWTNotActiveError() : super('jwt not active');
}
