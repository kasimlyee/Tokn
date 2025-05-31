const { JWTAuth } = require("../../lib/core");
const { createAuthMiddleware } = require("../../lib/middleware");
const express = require("express");
const request = require("supertest");

describe("Authentication Flow Integration", () => {
  let app;
  let jwtAuth;
  let accessToken;
  let refreshToken;

  beforeAll(() => {
    jwtAuth = new JWTAuth({
      secret: "integration-test-secret",
      algorithm: "HS256",
      accessTokenExpiry: "1m",
      refreshTokenExpiry: "5m",
      issuer: "integration-test",
      audience: "integration-test",
    });

    app = express();
    app.use(express.json());

    // Mock login endpoint
    app.post("/login", (req, res) => {
      const { username, password } = req.body;
      if (username === "testuser" && password === "testpass") {
        const payload = {
          userId: "123",
          username: "testuser",
          roles: ["user"],
        };
        accessToken = jwtAuth.generateAccessToken(payload);
        refreshToken = jwtAuth.generateRefreshToken(payload);
        res.json({ accessToken, refreshToken });
      } else {
        res.status(401).json({ error: "Invalid credentials" });
      }
    });

    // Protected endpoint
    app.get("/protected", createAuthMiddleware(jwtAuth), (req, res) => {
      res.json({ message: "Protected data", user: req.user });
    });

    // Token refresh endpoint
    app.post("/refresh", (req, res) => {
      const { refreshToken: token } = req.body;
      try {
        if (!jwtAuth.isRefreshTokenValid(token)) {
          throw new Error("Invalid refresh token");
        }

        const payload = jwtAuth.verifyToken(token);
        const newAccessToken = jwtAuth.generateAccessToken(payload);
        const newRefreshToken = jwtAuth.rotateRefreshToken(token, payload);

        res.json({
          accessToken: newAccessToken,
          refreshToken: newRefreshToken,
        });
      } catch (err) {
        res.status(401).json({ error: "Invalid refresh token" });
      }
    });

    // Logout endpoint
    app.post("/logout", createAuthMiddleware(jwtAuth), (req, res) => {
      jwtAuth.blacklistToken(req.token);
      jwtAuth.revokeRefreshToken(req.body.refreshToken);
      res.json({ message: "Logged out successfully" });
    });
  });

  test("should authenticate and access protected route", async () => {
    // Login to get tokens
    const loginRes = await request(app)
      .post("/login")
      .send({ username: "testuser", password: "testpass" });

    expect(loginRes.status).toBe(200);
    expect(loginRes.body.accessToken).toBeDefined();
    expect(loginRes.body.refreshToken).toBeDefined();

    // Access protected route with token
    const protectedRes = await request(app)
      .get("/protected")
      .set("Authorization", `Bearer ${loginRes.body.accessToken}`);

    expect(protectedRes.status).toBe(200);
    expect(protectedRes.body.message).toBe("Protected data");
    expect(protectedRes.body.user.username).toBe("testuser");
  });

  test("should reject invalid credentials", async () => {
    const res = await request(app)
      .post("/login")
      .send({ username: "wrong", password: "credentials" });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe("Invalid credentials");
  });

  test("should reject access without token", async () => {
    const res = await request(app).get("/protected");
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("Unauthorized");
  });

  test("should refresh access token", async () => {
    // First login
    const loginRes = await request(app)
      .post("/login")
      .send({ username: "testuser", password: "testpass" });

    // Refresh tokens
    const refreshRes = await request(app)
      .post("/refresh")
      .send({ refreshToken: loginRes.body.refreshToken });

    expect(refreshRes.status).toBe(200);
    expect(refreshRes.body.accessToken).toBeDefined();
    expect(refreshRes.body.refreshToken).toBeDefined();
    expect(refreshRes.body.refreshToken).not.toBe(loginRes.body.refreshToken);
  });

  test("should reject invalid refresh token", async () => {
    const res = await request(app)
      .post("/refresh")
      .send({ refreshToken: "invalid.token.here" });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe("Invalid refresh token");
  });

  test("should logout and invalidate tokens", async () => {
    // First login
    const loginRes = await request(app)
      .post("/login")
      .send({ username: "testuser", password: "testpass" });

    // Logout
    const logoutRes = await request(app)
      .post("/logout")
      .set("Authorization", `Bearer ${loginRes.body.accessToken}`)
      .send({ refreshToken: loginRes.body.refreshToken });

    expect(logoutRes.status).toBe(200);
    expect(logoutRes.body.message).toBe("Logged out successfully");

    // Try to use the access token after logout
    const protectedRes = await request(app)
      .get("/protected")
      .set("Authorization", `Bearer ${loginRes.body.accessToken}`);

    expect(protectedRes.status).toBe(401);
    expect(protectedRes.body.error).toBe("Unauthorized");
  });
});
