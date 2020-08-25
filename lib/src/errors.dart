class JWTError extends Error {
  JWTError(this.message);

  final String message;
}

/// An error thrown when toke is invalid
class JWTInvalidError extends JWTError {
  JWTInvalidError(String message) : super(message);
}

/// An error thrown when token is expired
class JWTExpiredError extends JWTError {
  JWTExpiredError() : super('jwt expired');
}
