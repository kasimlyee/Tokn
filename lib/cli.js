#!/usr/bin/env node
const { Command } = require("commander");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { JWTAuth } = require("./core");

const SecurityUtils = {
  generateRandomString(length = 32) {
    return crypto
      .randomBytes(Math.ceil(length / 2))
      .toString("hex")
      .slice(0, length);
  },

  hashPassword(password, salt = null) {
    const saltToUse = salt || this.generateRandomString(16);
    const hash = crypto
      .pbkdf2Sync(password, saltToUse, 100000, 64, "sha512")
      .toString("hex");

    return {
      salt: saltToUse,
      hash,
    };
  },

  generateKeyPair(type = "rsa", options = {}) {
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
  },
};

const program = new Command();

program
  .name("jwt-tokn")
  .description("CLI for JWT authentication management")
  .version("1.0.0");

program
  .command("generate-key")
  .description("Generate cryptographic keys")
  .option("-t, --type <type>", "Key type (rsa, ec)", "rsa")
  .option("-o, --output <dir>", "Output directory", ".")
  .option("--name <name>", "Base name for key files", "jwt")
  .action((options) => {
    try {
      const { publicKey, privateKey } = SecurityUtils.generateKeyPair(
        options.type
      );

      // Ensure output directory exists
      if (!fs.existsSync(options.output)) {
        fs.mkdirSync(options.output, { recursive: true });
      }

      const publicKeyPath = path.join(options.output, `${options.name}.pub`);
      const privateKeyPath = path.join(options.output, `${options.name}.key`);

      fs.writeFileSync(publicKeyPath, publicKey);
      fs.writeFileSync(privateKeyPath, privateKey);

      console.log(`Keys generated successfully:`);
      console.log(`Public key: ${publicKeyPath}`);
      console.log(`Private key: ${privateKeyPath}`);
    } catch (err) {
      console.error("Error generating keys:", err.message);
      process.exit(1);
    }
  });

program
  .command("generate-token")
  .description("Generate a JWT token")
  .requiredOption("-p, --payload <payload>", "JSON payload")
  .option("-s, --secret <secret>", "HMAC secret key")
  .option(
    "--private-key <file>",
    "Path to private key file (for RS/ES algorithms)"
  )
  .option("-a, --algorithm <alg>", "Algorithm (HS256, RS256, etc.)", "HS256")
  .option("-e, --expires <time>", "Expiration time (e.g., 15m, 1h, 7d)", "15m")
  .action((options) => {
    try {
      const payload = JSON.parse(options.payload);
      let authOptions = { algorithm: options.algorithm };

      if (options.secret) {
        authOptions.secret = options.secret;
      } else if (options.privateKey) {
        authOptions.privateKey = fs.readFileSync(options.privateKey, "utf8");
      } else {
        throw new Error("Either --secret or --private-key must be provided");
      }

      const jwtAuth = new JWTAuth({
        ...authOptions,
        accessTokenExpiry: options.expires,
      });
      const token = jwtAuth.generateAccessToken(payload);

      console.log("Generated token:");
      console.log(token);
    } catch (err) {
      console.error("Error generating token:", err.message);
      process.exit(1);
    }
  });

program
  .command("verify-token")
  .description("Verify a JWT token")
  .requiredOption("-t, --token <token>", "JWT token to verify")
  .option("-s, --secret <secret>", "HMAC secret key")
  .option(
    "--public-key <file>",
    "Path to public key file (for RS/ES algorithms)"
  )
  .requiredOption("-a, --algorithm <alg>", "Algorithm (HS256, RS256, etc.)")
  .action((options) => {
    try {
      const authOptions = {
        algorithm: options.algorithm,
      };

      if (options.algorithm.startsWith("HS")) {
        if (!options.secret) {
          throw new Error("Secret key is required for HMAC algorithms");
        }
        authOptions.secret = options.secret;
      } else if (
        options.algorithm.startsWith("RS") ||
        options.algorithm.startsWith("ES")
      ) {
        if (!options.publicKey) {
          throw new Error("Public key is required for RSA/ECDSA algorithms");
        }
        authOptions.publicKey = fs.readFileSync(options.publicKey, "utf8");
      } else {
        throw new Error(`Unsupported algorithm: ${options.algorithm}`);
      }

      const jwtAuth = new JWTAuth(authOptions);
      const payload = jwtAuth.verifyToken(options.token);

      console.log("Token is valid. Payload:");
      console.log(JSON.stringify(payload, null, 2));
    } catch (err) {
      console.error("Token verification failed:", err.message);
      process.exit(1);
    }
  });

program
  .command("hash-password")
  .description("Hash a password for secure storage")
  .requiredOption("-p, --password <password>", "Password to hash")
  .option("-s, --salt <salt>", "Optional salt (will generate if not provided)")
  .action((options) => {
    try {
      const { hash, salt } = SecurityUtils.hashPassword(
        options.password,
        options.salt
      );

      console.log("Password hashed successfully:");
      console.log(`Salt: ${salt}`);
      console.log(`Hash: ${hash}`);
    } catch (err) {
      console.error("Error hashing password:", err.message);
      process.exit(1);
    }
  });

program.parse(process.argv);
