const crypto = require("crypto");

class SecurityUtils {
  static generateRandomString(length = 32) {
    return crypto
      .randomBytes(Math.ceil(length / 2))
      .toString("hex")
      .slice(0, length);
  }

  static hashPassword(password, salt = null) {
    const saltToUse = salt || SecurityUtils.generateRandomString(16);
    const hash = crypto
      .pbkdf2Sync(password, saltToUse, 100000, 64, "sha512")
      .toString("hex");

    return {
      salt: saltToUse,
      hash,
    };
  }
  static verifyPassword(password, hash, salt) {
    const newHash = SecurityUtils.hashPassword(password, salt).hash;
    return newHash === hash;
  }

  static generateKeyPair(type = "rsa", options = {}) {
    switch (type.toLowerCase()) {
      case "rsa":
        return crypto.generateKeyPairSync("rsa", {
          modulusLength: options.modulusLength || 2048,
          publicKeyEncoding: {
            type: "spki",
            format: "pem",
          },
          privateKeyEncoding: {
            type: "pkcs8",
            format: "pem",
          },
        });
      case "ec":
        return crypto.generateKeyPairSync("ec", {
          namedCurve: options.namedCurve || "secp256k1",
          publicKeyEncoding: {
            type: "spki",
            format: "pem",
          },
          privateKeyEncoding: {
            type: "pkcs8",
            format: "pem",
          },
        });
      default:
        throw new Error("Unsupported key pair type");
    }
  }

  static generateCsrfToken() {
    return SecurityUtils.generateRandomString(32);
  }

  static constantTimeCompare(a, b) {
    const aBuffer = Buffer.from(a);
    const bBuffer = Buffer.from(b);

    if (aBuffer.length !== bBuffer.length) {
      return false;
    }

    return crypto.timingSafeEqual(aBuffer, bBuffer);
  }
}

module.exports = SecurityUtils;
