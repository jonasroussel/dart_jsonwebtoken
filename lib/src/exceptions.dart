/// JWTException objects thrown in the case of a jwt sign or verify failure.
class JWTException implements Exception {
  JWTException(this.message);

  final String message;

  @override
  String toString() => 'JWTException: $message';
}

/// An exception thrown when jwt is invalid
class JWTInvalidException extends JWTException {
  JWTInvalidException(String message) : super(message);

  @override
  String toString() => 'JWTInvalidException: $message';
}

/// An exception thrown when jwt is expired
class JWTExpiredException extends JWTException {
  JWTExpiredException() : super('jwt expired');

  @override
  String toString() => 'JWTExpiredException: $message';
}

/// An exception thrown when jwt is not active
class JWTNotActiveException extends JWTException {
  JWTNotActiveException() : super('jwt not active');

  @override
  String toString() => 'JWTNotActiveException: $message';
}

/// An exception thrown when parsing failed
class JWTParseException extends JWTException {
  JWTParseException(String message) : super(message);

  @override
  String toString() => 'JWTParseException: $message';
}

/// An exception thrown by default
class JWTUndefinedException extends JWTException {
  JWTUndefinedException(Exception ex, this.stackTrace) : super(ex.toString());

  final StackTrace stackTrace;

  @override
  String toString() => 'JWTUndefinedException: $message';
}
