const SecurityUtils = require("../../lib/security");
const crypto = require("crypto");

describe("Security Utilities", () => {
  const password = "securepassword123";
  describe("generateRandomString", () => {
    test("should generate string of specified length", () => {
      const str = SecurityUtils.generateRandomString(32);
      expect(str).toHaveLength(32);
      expect(typeof str).toBe("string");
    });

    test("should generate different strings each time", () => {
      const str1 = SecurityUtils.generateRandomString(16);
      const str2 = SecurityUtils.generateRandomString(16);
      expect(str1).not.toBe(str2);
    });
  });

  describe("Password Hashing", () => {
    test("should generate hash and salt", () => {
      const { hash, salt } = SecurityUtils.hashPassword(password);
      expect(hash).toBeDefined();
      expect(salt).toBeDefined();
      expect(hash).toHaveLength(128);
      expect(salt.length).toBeGreaterThanOrEqual(8);
    });

    test("should generate same hash with same salt", () => {
      const salt = SecurityUtils.generateRandomString(16);
      const { hash: hash1 } = SecurityUtils.hashPassword(password, salt);
      const { hash: hash2 } = SecurityUtils.hashPassword(password, salt);
      expect(hash1).toBe(hash2);
    });

    test("should verify correct password", () => {
      const { hash, salt } = SecurityUtils.hashPassword(password);
      const isValid = SecurityUtils.verifyPassword(password, hash, salt);
      expect(isValid).toBe(true);
    });

    test("should reject incorrect password", () => {
      const { hash, salt } = SecurityUtils.hashPassword(password);
      const isValid = SecurityUtils.verifyPassword("wrongpassword", hash, salt);
      expect(isValid).toBe(false);
    });
  });

  describe("Key Pair Generation", () => {
    test("should generate RSA key pair", () => {
      const { publicKey, privateKey } = SecurityUtils.generateKeyPair("rsa");
      expect(publicKey).toBeDefined();
      expect(privateKey).toBeDefined();
      expect(publicKey).toContain("-----BEGIN PUBLIC KEY-----");
      expect(privateKey).toContain("-----BEGIN PRIVATE KEY-----");
    });

    test("should generate EC key pair", () => {
      const { publicKey, privateKey } = SecurityUtils.generateKeyPair("ec");
      expect(publicKey).toBeDefined();
      expect(privateKey).toBeDefined();
      expect(publicKey).toContain("-----BEGIN PUBLIC KEY-----");
      expect(privateKey).toContain("-----BEGIN PRIVATE KEY-----");
    });

    test("should throw error for invalid key type", () => {
      expect(() => SecurityUtils.generateKeyPair("invalid")).toThrow();
    });
  });

  describe("CSRF Protection", () => {
    test("should generate CSRF token", () => {
      const token = SecurityUtils.generateCsrfToken();
      expect(token).toBeDefined();
      expect(token).toHaveLength(32);
    });
  });

  describe("Constant Time Comparison", () => {
    test("should return true for equal strings", () => {
      const result = SecurityUtils.constantTimeCompare("test", "test");
      expect(result).toBe(true);
    });

    test("should return false for different strings", () => {
      const result = SecurityUtils.constantTimeCompare("test1", "test2");
      expect(result).toBe(false);
    });

    test("should return false for different length strings", () => {
      const result = SecurityUtils.constantTimeCompare("short", "longer");
      expect(result).toBe(false);
    });
  });
});
