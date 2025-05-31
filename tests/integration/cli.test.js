const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const { promisify } = require("util");

const execAsync = promisify(exec);
const readFileAsync = promisify(fs.readFile);
const unlinkAsync = promisify(fs.unlink);
const mkdirAsync = promisify(fs.mkdir);
const rmdirAsync = promisify(fs.rm);

describe("CLI Tool", () => {
  const cliPath = path.join(__dirname, "../../lib/cli.js");
  const testPayload = JSON.stringify({ userId: "test", roles: ["user"] });
  let keyFiles = [];
  let tempKeyDir;

  beforeAll(async () => {
    tempKeyDir = path.join(__dirname, "temp-keys");
    try {
      await mkdirAsync(tempKeyDir, { recursive: true });
    } catch (err) {
      if (err.code !== "EEXIST") throw err;
    }
  });

  afterAll(async () => {
    // Clean up generated key files
    await Promise.all(
      keyFiles.map((file) => unlinkAsync(file).catch(() => {}))
    );

    // Remove directory recursively
    try {
      await rmdirAsync(tempKeyDir, { recursive: true, force: true });
    } catch (err) {
      if (err.code !== "ENOENT") throw err;
    }
  });

  test("should generate RSA key pair", async () => {
    const keyName = "test-key";
    const pubKeyPath = path.join(tempKeyDir, `${keyName}.pub`);
    const privKeyPath = path.join(tempKeyDir, `${keyName}.key`);

    const { stdout } = await execAsync(
      `node ${cliPath} generate-key --type rsa --output ${tempKeyDir} --name ${keyName}`
    );

    expect(stdout).toContain("Keys generated successfully");
    expect(stdout).toContain(pubKeyPath);
    expect(stdout).toContain(privKeyPath);

    // Verify files exist
    const [pubKey, privKey] = await Promise.all([
      readFileAsync(pubKeyPath, "utf8"),
      readFileAsync(privKeyPath, "utf8"),
    ]);

    expect(pubKey).toContain("-----BEGIN PUBLIC KEY-----");
    expect(privKey).toContain("-----BEGIN PRIVATE KEY-----");

    // Add to cleanup list
    keyFiles.push(pubKeyPath, privKeyPath);
  });

  test("should generate JWT token with HS256", async () => {
    const { stdout } = await execAsync(
      `node ${cliPath} generate-token -p '${testPayload}' -s test-secret -a HS256`
    );

    expect(stdout).toContain("Generated token:");
    const token = stdout.trim().split("\n").pop();
    expect(token.split(".")).toHaveLength(3);
  });

  test("should hash password", async () => {
    const password = "securepassword123";
    const { stdout } = await execAsync(
      `node ${cliPath} hash-password -p ${password}`
    );

    expect(stdout).toContain("Password hashed successfully");
    expect(stdout).toContain("Salt:");
    expect(stdout).toContain("Hash:");
  });

  test("should fail with missing required options", async () => {
    await expect(
      execAsync(`node ${cliPath} generate-token -p '${testPayload}'`)
    ).rejects.toThrow();
  });

  test("should fail with invalid token verification", async () => {
    await expect(
      execAsync(
        `node ${cliPath} verify-token -t invalid.token.here -s test-secret`
      )
    ).rejects.toThrow();
  });
});
