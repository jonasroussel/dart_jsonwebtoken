/// JWTError objects thrown in the case of a jwt sign or verify failure.
class JWTError extends Error {
  JWTError(this.message);

  /// Describes the error thrown
  final String message;

  @override
  String toString() => 'JWTError: $message';
}

/// An error thrown when jwt is invalid
class JWTInvalidError extends JWTError {
  JWTInvalidError(String message) : super(message);
}

/// An error thrown when jwt is expired
class JWTExpiredError extends JWTError {
  JWTExpiredError() : super('jwt expired');
}

/// An error thrown when jwt is not active
class JWTNotActiveError extends JWTError {
  JWTNotActiveError() : super('jwt not active');
}

/// An error thrown when parsing failed
class JWTParseError extends JWTError {
  JWTParseError(String message) : super(message);
}
