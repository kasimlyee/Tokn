const { JWTAuth } = require("../lib/core");
const {
  createAuthMiddleware,
  createRoleMiddleware,
} = require("../lib/middleware");

// Initialize JWT auth with HS256 algorithm
const jwtAuth = new JWTAuth({
  secret: "your-very-secure-secret-key",
  algorithm: "HS256",
  accessTokenExpiry: "15m",
  refreshTokenExpiry: "7d",
  issuer: "your-app",
  audience: "your-app-users",
});

// Generate tokens
const payload = { userId: "123", roles: ["user"] };
const accessToken = jwtAuth.generateAccessToken(payload);
const refreshToken = jwtAuth.generateRefreshToken(payload);

console.log("Access Token:", accessToken);
console.log("Refresh Token:", refreshToken);

// Verify token
try {
  const verifiedPayload = jwtAuth.verifyToken(accessToken);
  console.log("Verified Payload:", verifiedPayload);
} catch (err) {
  console.error("Token verification failed:", err.message);
}

// Example with Express
const express = require("express");
const app = express();

// Apply auth middleware
const authMiddleware = createAuthMiddleware(jwtAuth);
const adminMiddleware = createRoleMiddleware("admin");

app.get("/protected", authMiddleware, (req, res) => {
  res.json({ message: "Access granted", user: req.user });
});

app.get("/admin", authMiddleware, adminMiddleware, (req, res) => {
  res.json({ message: "Admin access granted", user: req.user });
});

app.listen(3000, () => console.log("Server running on port 3000"));
