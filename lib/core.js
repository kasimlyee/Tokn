const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const TokenStorage = require("./storage");

class JWTError extends Error {
  constructor(message, code = "JWT_ERROR") {
    super(message);
    this.name = "JWTError";
    this.code = code;
  }
}

class JWTAuth {
  constructor(options = {}) {
    this.options = {
      algorithm: "HS256",
      accessTokenExpiry: "15m",
      refreshTokenExpiry: "30d",
      issuer: "jwt-auth-library",
      audience: "example.com",
      ...options,
    };

    this.validateOptions();
    this.initKeys();
    this.tokenBlacklist = new Set();
    this.refreshTokenWhitelist = new Set();
    this.refreshTokenStore = new TokenStorage(
      options.tokenStorage || { storage: "memory" }
    );
  }

  isRefreshTokenValid(token) {
    return this.refreshTokenStore.has(`refresh:${token}`);
  }

  validateOptions() {
    const supportedAlgorithms = [
      "HS256",
      "HS384",
      "HS512",
      "RS256",
      "RS384",
      "RS512",
      "ES256",
      "ES384",
    ];
    if (!supportedAlgorithms.includes(this.options.algorithm)) {
      throw new JWTError(`Unsupported algorithm: ${this.options.algorithm}`);
    }

    if (!this.options.secret && !this.options.privateKey) {
      throw new JWTError("Either secret or privateKey must be provided");
    }
  }

  initKeys() {
    if (this.options.algorithm.startsWith("HS")) {
      if (!this.options.secret) {
        throw new JWTError("Secret key is required for HMAC algorithms");
      }
      this.secret = this.options.secret;
    } else if (
      this.options.algorithm.startsWith("RS") ||
      this.options.algorithm.startsWith("ES")
    ) {
      if (!this.options.publicKey && !this.options.privateKey) {
        throw new JWTError(
          "Public key or private key is required for RSA/ECDSA algorithms"
        );
      }
      this.publicKey = this.options.publicKey;
      this.privateKey = this.options.privateKey;
    }
  }
  static parseTime(timeString) {
    const unit = timeString.slice(-1);
    const value = parseInt(timeString.slice(0, -1), 10);

    switch (unit) {
      case "s":
        return value * 1000;
      case "m":
        return value * 60 * 1000;
      case "h":
        return value * 60 * 60 * 1000;
      case "d":
        return value * 24 * 60 * 60 * 1000;
      default:
        throw new JWTError(`Invalid time unit: ${unit}`);
    }
  }

  async isRefreshTokenValid(token) {
    try {
      // First verify the token is structurally valid
      this.verifyToken(token);

      // Then check if it exists in the store
      return await this.refreshTokenStore.has(`refresh:${token}`);
    } catch (err) {
      return false;
    }
  }

  generateAccessToken(payload) {
    return this.generateToken(payload, this.options.accessTokenExpiry);
  }

  generateRefreshToken(payload) {
    const token = this.generateToken(payload, this.options.refreshTokenExpiry);
    this.refreshTokenStore.set(
      `refresh:${token}`,
      "valid",
      JWTAuth.parseTime(this.options.refreshTokenExpiry)
    );
    return token;
  }

  generateToken(payload, expiresIn) {
    const header = {
      alg: this.options.algorithm,
      typ: "JWT",
    };

    // Ensure unique iat by adding a small random delay if needed
    const now = Math.floor(Date.now() / 1000);
    const expiry = Math.floor(
      (Date.now() + JWTAuth.parseTime(expiresIn)) / 1000
    );

    const claims = {
      ...payload,
      iss: this.options.issuer,
      aud: this.options.audience,
      iat: now,
      exp: expiry,
      jti: crypto.randomBytes(8).toString("hex"), // Add unique JWT ID
    };

    const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
    const encodedPayload = this.base64UrlEncode(JSON.stringify(claims));
    const signature = this.signToken(`${encodedHeader}.${encodedPayload}`);

    return `${encodedHeader}.${encodedPayload}.${signature}`;
  }

  signToken(input) {
    try {
      let signature;
      if (this.options.algorithm.startsWith("HS")) {
        signature = crypto
          .createHmac(this.getHashAlgorithm(), this.secret)
          .update(input)
          .digest("base64")
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=+$/, "");
      } else {
        signature = crypto
          .createSign(this.getHashAlgorithm())
          .update(input)
          .sign(this.privateKey, "base64")
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=+$/, "");
      }
      return signature;
    } catch (err) {
      throw new JWTError(`Failed to sign token: ${err.message}`);
    }
  }

  getHashAlgorithm() {
    switch (this.options.algorithm) {
      case "HS256":
      case "RS256":
      case "ES256":
        return "sha256";
      case "HS384":
      case "RS384":
      case "ES384":
        return "sha384";
      case "HS512":
      case "RS512":
      case "ES512":
        return "sha512";
      default:
        return "sha256";
    }
  }

  verifyToken(token, options = {}) {
    if (this.tokenBlacklist.has(token)) {
      throw new JWTError("Token has been blacklisted", "TOKEN_BLACKLISTED");
    }

    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new JWTError("Invalid token format", "INVALID_TOKEN");
    }

    const [encodedHeader, encodedPayload, signature] = parts;
    const header = JSON.parse(this.base64UrlDecode(encodedHeader));
    const payload = JSON.parse(this.base64UrlDecode(encodedPayload));

    // Verify algorithm
    if (header.alg !== this.options.algorithm) {
      throw new JWTError("Token algorithm mismatch", "ALGORITHM_MISMATCH");
    }

    // Verify signature
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const isSignatureValid = this.verifySignature(
      signingInput,
      signature,
      header.alg
    );
    if (!isSignatureValid) {
      throw new JWTError("Invalid token signature", "INVALID_SIGNATURE");
    }

    // Verify expiration
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      throw new JWTError("Token has expired", "TOKEN_EXPIRED");
    }

    // Verify issuer if required
    if (options.verifyIssuer !== false && payload.iss !== this.options.issuer) {
      throw new JWTError("Invalid token issuer", "INVALID_ISSUER");
    }

    // Verify audience if required
    if (
      options.verifyAudience !== false &&
      payload.aud !== this.options.audience
    ) {
      throw new JWTError("Invalid token audience", "INVALID_AUDIENCE");
    }

    return payload;
  }

  verifySignature(input, signature, algorithm) {
    try {
      if (algorithm.startsWith("HS")) {
        const expectedSignature = crypto
          .createHmac(this.getHashAlgorithm(), this.secret)
          .update(input)
          .digest("base64")
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=+$/, "");
        return expectedSignature === signature;
      } else {
        return crypto
          .createVerify(this.getHashAlgorithm())
          .update(input)
          .verify(this.publicKey, signature, "base64");
      }
    } catch (err) {
      throw new JWTError(`Signature verification failed: ${err.message}`);
    }
  }

  base64UrlEncode(str) {
    return Buffer.from(str)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  base64UrlDecode(str) {
    let padded = str;
    while (padded.length % 4) {
      padded += "=";
    }
    return Buffer.from(
      padded.replace(/-/g, "+").replace(/_/g, "/"),
      "base64"
    ).toString();
  }

  blacklistToken(token) {
    this.tokenBlacklist.add(token);
  }

  revokeRefreshToken(token) {
    this.refreshTokenStore.delete(`refresh:${token}`);
  }

  rotateRefreshToken(oldToken, payload) {
    this.revokeRefreshToken(oldToken);
    return this.generateRefreshToken(payload);
  }
}

module.exports = {
  JWTAuth,
  JWTError,
};
