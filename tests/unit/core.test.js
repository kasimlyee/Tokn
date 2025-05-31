const { JWTAuth, JWTError } = require("../../lib/core");
const crypto = require("crypto");
const TokenStorage = require("../../lib/storage");

describe("JWTAuth Core Functionality", () => {
  let jwtAuthHS256;
  let jwtAuthRS256;
  let privateKey, publicKey;

  beforeAll(() => {
    // Generate RSA key pair for testing
    const { privateKey: pk, publicKey: pubk } = crypto.generateKeyPairSync(
      "rsa",
      {
        modulusLength: 2048,
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      }
    );
    privateKey = pk;
    publicKey = pubk;

    // Initialize JWT auth instances with memory storage
    jwtAuthHS256 = new JWTAuth({
      secret: "test-secret-123",
      algorithm: "HS256",
      accessTokenExpiry: "1m",
      refreshTokenExpiry: "1h",
      tokenStorage: { storage: "memory" },
    });

    jwtAuthRS256 = new JWTAuth({
      algorithm: "RS256",
      privateKey,
      publicKey,
      accessTokenExpiry: "1m",
      refreshTokenExpiry: "1h",
      tokenStorage: { storage: "memory" },
    });
  });

  describe("Token Generation", () => {
    test("should generate valid HS256 token", () => {
      const payload = { userId: "123", roles: ["user"] };
      const token = jwtAuthHS256.generateAccessToken(payload);
      expect(token).toBeDefined();
      expect(token.split(".")).toHaveLength(3);
    });

    test("should generate valid RS256 token", () => {
      const payload = { userId: "123", roles: ["user"] };
      const token = jwtAuthRS256.generateAccessToken(payload);
      expect(token).toBeDefined();
      expect(token.split(".")).toHaveLength(3);
    });

    test("should include standard claims in token", () => {
      const payload = { userId: "123" };
      const token = jwtAuthHS256.generateAccessToken(payload);
      const parts = token.split(".");
      const decoded = JSON.parse(Buffer.from(parts[1], "base64").toString());

      expect(decoded).toHaveProperty("iat");
      expect(decoded).toHaveProperty("exp");
      expect(decoded).toHaveProperty("iss");
      expect(decoded).toHaveProperty("aud");
      expect(decoded.userId).toBe("123");
    });

    test("should generate different tokens for same payload", () => {
      const payload = { userId: "123" };
      const token1 = jwtAuthHS256.generateAccessToken(payload);
      const token2 = jwtAuthHS256.generateAccessToken(payload);
      expect(token1).not.toBe(token2);
    });
  });

  describe("Token Verification", () => {
    test("should verify valid HS256 token", () => {
      const payload = { userId: "123" };
      const token = jwtAuthHS256.generateAccessToken(payload);
      const verified = jwtAuthHS256.verifyToken(token);
      expect(verified.userId).toBe("123");
    });

    test("should verify valid RS256 token", () => {
      const payload = { userId: "123" };
      const token = jwtAuthRS256.generateAccessToken(payload);
      const verified = jwtAuthRS256.verifyToken(token);
      expect(verified.userId).toBe("123");
    });

    test("should throw error for expired token", () => {
      const expiredAuth = new JWTAuth({
        secret: "test-secret-123",
        algorithm: "HS256",
        accessTokenExpiry: "-1s", // Expired 1 second ago
      });

      const payload = { userId: "123" };
      const token = expiredAuth.generateAccessToken(payload);

      expect(() => expiredAuth.verifyToken(token)).toThrow(JWTError);
      expect(() => expiredAuth.verifyToken(token)).toThrow("Token has expired");
    });

    test("should throw error for invalid signature", () => {
      const payload = { userId: "123" };
      const token = jwtAuthHS256.generateAccessToken(payload);
      const [header, payloadPart] = token.split(".");
      const fakeToken = `${header}.${payloadPart}.fakeSignature`;

      expect(() => jwtAuthHS256.verifyToken(fakeToken)).toThrow(JWTError);
      expect(() => jwtAuthHS256.verifyToken(fakeToken)).toThrow(
        "Invalid token signature"
      );
    });

    test("should throw error for tampered payload", () => {
      const payload = { userId: "123" };
      const token = jwtAuthHS256.generateAccessToken(payload);
      const [header, payloadPart, signature] = token.split(".");
      const tamperedPayload = Buffer.from(
        JSON.stringify({ userId: "456" })
      ).toString("base64");
      const tamperedToken = `${header}.${tamperedPayload}.${signature}`;

      expect(() => jwtAuthHS256.verifyToken(tamperedToken)).toThrow(JWTError);
      expect(() => jwtAuthHS256.verifyToken(tamperedToken)).toThrow(
        "Invalid token signature"
      );
    });

    test("should throw error for blacklisted token", () => {
      const payload = { userId: "123" };
      const token = jwtAuthHS256.generateAccessToken(payload);
      jwtAuthHS256.blacklistToken(token);

      expect(() => jwtAuthHS256.verifyToken(token)).toThrow(JWTError);
      expect(() => jwtAuthHS256.verifyToken(token)).toThrow(
        "Token has been blacklisted"
      );
    });
  });

  describe("Refresh Tokens", () => {
    test("should generate and validate refresh token", async () => {
      const payload = { userId: "123" };
      const token = await jwtAuthHS256.generateRefreshToken(payload);
      const isValid = await jwtAuthHS256.isRefreshTokenValid(token);
      expect(isValid).toBe(true);
    });

    test("should invalidate refresh token after revocation", async () => {
      const payload = { userId: "123" };
      const token = await jwtAuthHS256.generateRefreshToken(payload);
      await jwtAuthHS256.revokeRefreshToken(token);
      const isValid = await jwtAuthHS256.isRefreshTokenValid(token);
      expect(isValid).toBe(false);
    });

    test("should rotate refresh token", async () => {
      const payload = { userId: "123" };
      const oldToken = await jwtAuthHS256.generateRefreshToken(payload);
      const newToken = await jwtAuthHS256.rotateRefreshToken(oldToken, payload);

      const oldValid = await jwtAuthHS256.isRefreshTokenValid(oldToken);
      const newValid = await jwtAuthHS256.isRefreshTokenValid(newToken);

      expect(oldValid).toBe(false);
      expect(newValid).toBe(true);
    });
  });

  describe("Error Handling", () => {
    test("should throw error for invalid algorithm", () => {
      expect(() => new JWTAuth({ algorithm: "INVALID" })).toThrow(JWTError);
    });

    test("should throw error for missing secret/key", () => {
      expect(() => new JWTAuth({ algorithm: "HS256" })).toThrow(JWTError);
      expect(() => new JWTAuth({ algorithm: "RS256" })).toThrow(JWTError);
    });

    test("should throw error for malformed token", () => {
      expect(() => jwtAuthHS256.verifyToken("malformed.token")).toThrow(
        JWTError
      );
      expect(() => jwtAuthHS256.verifyToken("malformed.token")).toThrow(
        "Invalid token format"
      );
    });
  });
});
