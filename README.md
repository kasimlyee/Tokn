# JWT Authentication Library (jwt-tokn)

[![npm version](https://img.shields.io/npm/v/jwt-auth-library.svg?style=flat-square)](https://www.npmjs.com/package/jwt-auth-library)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/actions/workflow/status/kasimlyee/jwt-auth-library/ci.yml?style=flat-square)](https://github.com/kasimlyee/jwt-auth-library/actions)

A secure and robust JWT authentication library for Node.js applications with built-in security best practices.

## Features

- 🔒 Secure token generation and verification
- ⏳ Token expiration and refresh mechanism
- 🛡️ Support for HS256, RS256, and ES256 algorithms
- 🔄 Refresh token rotation
- 🛂 Role-based access control
- 🗄️ Redis and in-memory storage options
- 🔧 Comprehensive CLI tool
- ✅ 100% test coverage

## Installation

```bash
npm install jwt-tokn
# or
yarn add jwt-tokn
```

## Quick Start

### Basic Usage

```javascript
const { JWTAuth } = require('jwt-tokn');

// Initialize with HS256 algorithm
const jwtAuth = new JWTAuth({
  secret: 'your-secure-secret-key',
  algorithm: 'HS256',
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '7d'
});

// Generate tokens
const payload = { userId: '123', roles: ['user'] };
const accessToken = jwtAuth.generateAccessToken(payload);
const refreshToken = jwtAuth.generateRefreshToken(payload);

// Verify token
try {
  const verified = jwtAuth.verifyToken(accessToken);
  console.log('Verified payload:', verified);
} catch (err) {
  console.error('Verification failed:', err.message);
}
```

### Express Middleware

```javascript
const express = require('express');
const { createAuthMiddleware, createRoleMiddleware } = require('jwt-tokn');

const app = express();
const authMiddleware = createAuthMiddleware(jwtAuth);
const adminMiddleware = createRoleMiddleware('admin');

// Protected route
app.get('/profile', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

// Admin-only route
app.get('/admin', authMiddleware, adminMiddleware, (req, res) => {
  res.json({ message: 'Admin dashboard' });
});
```

## Configuration Options

### JWTAuth Constructor

| Option             | Type     | Default               | Description |
|--------------------|----------|-----------------------|-------------|
| `algorithm`        | string   | `'HS256'`             | Algorithm to use (HS256, RS256, ES256) |
| `secret`           | string   | -                     | Required for HS* algorithms |
| `privateKey`       | string   | -                     | Required for RS*/ES* algorithms |
| `publicKey`        | string   | -                     | Required for RS*/ES* verification |
| `accessTokenExpiry`| string   | `'15m'`               | Access token expiration (e.g., '15m', '1h') |
| `refreshTokenExpiry`| string  | `'7d'`                | Refresh token expiration |
| `issuer`           | string   | `'jwt-auth-tokn'`  | Token issuer |
| `audience`         | string   | `'example.com'`       | Token audience |
| `tokenStorage`     | object   | `{ storage: 'memory' }`| Storage configuration |

## CLI Tool

The package includes a command-line interface for key management and testing:

```bash
# Generate RSA key pair
npx jwt-tokn generate-key --type rsa --output ./keys

# Generate JWT token
npx jwt-tokn generate-token -p '{"userId":"123"}' -s your-secret

# Verify JWT token
npx jwt-tokn verify-token -t your.token.here -s your-secret

# Hash password
npx jwt-tokn hash-password -p "your-password"
```

## Security Best Practices

1. **Always use HTTPS** in production
2. **Keep access tokens short-lived** (15-30 minutes recommended)
3. **Store refresh tokens securely** with strict expiration
4. **Use appropriate algorithm**:
   - HS256 for simpler setups
   - RS256/ES256 for better security
5. **Rotate secrets/keys** periodically
6. **Implement token blacklisting** for logout functionality
7. **Never store sensitive data** in tokens

## Error Handling

The library throws specific error types you can catch:

```javascript
const { JWTError, TokenExpiredError, InvalidTokenError } = require('jwt-tokn');

try {
  jwtAuth.verifyToken(token);
} catch (err) {
  if (err instanceof TokenExpiredError) {
    // Handle expired token
  } else if (err instanceof InvalidTokenError) {
    // Handle invalid token
  } else {
    // Other errors
  }
}
```

## Examples

### Using RS256 Algorithm

```javascript
const fs = require('fs');
const { JWTAuth } = require('jwt-tokn');

const jwtAuth = new JWTAuth({
  algorithm: 'RS256',
  privateKey: fs.readFileSync('./private.key'),
  publicKey: fs.readFileSync('./public.key'),
  accessTokenExpiry: '1h'
});
```

### Refresh Token Flow

```javascript
async function refreshAccessToken(refreshToken) {
  if (!jwtAuth.isRefreshTokenValid(refreshToken)) {
    throw new Error('Invalid refresh token');
  }

  const payload = jwtAuth.verifyToken(refreshToken);
  const newAccessToken = jwtAuth.generateAccessToken(payload);
  const newRefreshToken = jwtAuth.rotateRefreshToken(refreshToken, payload);
  
  return { newAccessToken, newRefreshToken };
}
```

## Support

For issues and feature requests, please [open an issue](https://github.com/Tokn/issues).

## License

MIT © [Kasim Lyee](mailto:kasiimlyee@gmail.com)
