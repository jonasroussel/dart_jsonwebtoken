# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`dart_jsonwebtoken` is a Dart library for signing, verifying, and decoding JSON Web Tokens (RFC 7519). It supports all standard JWT algorithms: HMAC (HS256/384/512), RSA (RS256/384/512), RSA-PSS (PS256/384/512), ECDSA (ES256/ES256K/ES384/ES512), and EdDSA.

## Common Commands

```bash
dart pub get                  # Install dependencies
dart test                     # Run all tests
dart test test/sign_test.dart # Run a single test file
dart test -n "test name"      # Run tests matching a name
dart format .                 # Format code
dart analyze --fatal-infos    # Lint (CI fails on infos)
```

CI runs tests on both Chrome and VM with randomized ordering:
```bash
dart test -p chrome,vm --test-randomize-ordering-seed=random
```

## Architecture

The public API is exported through `lib/dart_jsonwebtoken.dart` which re-exports four modules:

- **`jwt.dart`** - Core `JWT` class with static `verify`/`tryVerify`/`decode`/`tryDecode` methods and instance `sign`/`trySign`. Also contains the `Audience` class (extends `ListBase<String>`). The `try*` variants return null instead of throwing.
- **`algorithms.dart`** - Abstract `JWTAlgorithm` with concrete implementations: `HMACAlgorithm`, `RSAAlgorithm`, `ECDSAAlgorithm`, `EdDSAAlgorithm`. Each implements `sign()` and `verify()`. Algorithm constants are accessed as `JWTAlgorithm.HS256`, etc.
- **`keys.dart`** - Key types inheriting from abstract `JWTKey`: `SecretKey`, `RSAPrivateKey`/`RSAPublicKey`, `ECPrivateKey`/`ECPublicKey`, `EdDSAPrivateKey`/`EdDSAPublicKey`. Keys can be constructed from PEM strings, raw bytes, or JWK (`JWTKey.fromJWK()`). All key types implement `toJWK()`.
- **`exceptions.dart`** - Exception hierarchy rooted at `JWTException`: `JWTInvalidException`, `JWTExpiredException`, `JWTNotActiveException`, `JWTParseException`, `JWTUndefinedException`.

Internal (non-exported) modules:
- **`key_parser.dart`** - ASN1/PEM parsing for all key types (RSA, EC, EdDSA). Handles both PKCS#1 and PKCS#8 formats.
- **`helpers.dart`** - Base64 padding/unpadding, BigInt encoding, time utilities, curve name mapping, constant-time comparison.

## Key Dependencies

- `pointycastle` - RSA and ECDSA cryptographic operations
- `ed25519_edwards` - EdDSA (Ed25519) operations
- `clock` - Testable time via `clock.now()` (used in `helpers.dart:timeNowUTC()`)
- `fake_async` (dev) - Time manipulation in tests

## Testing Notes

- Test keys are defined in `test/keys_const.dart` (PEM constants shared across test files)
- Tests are organized by operation: `sign_test.dart`, `verify_test.dart`, `decode_test.dart`, `header_test.dart`, `payload_test.dart`, `keys_test.dart`
- Time-dependent tests use `fake_async` + `clock` package to control `DateTime.now()`
