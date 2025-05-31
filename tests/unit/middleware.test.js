const {
  createAuthMiddleware,
  createRoleMiddleware,
} = require("../../lib/middleware");
const { JWTAuth } = require("../../lib/core");
const { JWTError } = require("../../lib/core");

describe("Authentication Middleware", () => {
  let jwtAuth;
  let authMiddleware;
  let req, res, next;

  beforeEach(() => {
    jwtAuth = new JWTAuth({
      secret: "test-secret-123",
      algorithm: "HS256",
      accessTokenExpiry: "1m",
    });

    authMiddleware = createAuthMiddleware(jwtAuth);

    req = {
      headers: {},
      cookies: {},
      query: {},
      body: {},
    };

    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    next = jest.fn();
  });

  test("should authenticate with valid token in Authorization header", () => {
    const payload = { userId: "123" };
    const token = jwtAuth.generateAccessToken(payload);
    req.headers.authorization = `Bearer ${token}`;

    authMiddleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.user).toEqual(expect.objectContaining(payload));
    expect(req.token).toBe(token);
  });

  test("should authenticate with valid token in cookie", () => {
    const cookieMiddleware = createAuthMiddleware(jwtAuth, {
      cookie: { name: "token" },
    });
    const payload = { userId: "123" };
    const token = jwtAuth.generateAccessToken(payload);
    req.cookies.token = token;

    cookieMiddleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.user).toEqual(expect.objectContaining(payload));
  });

  test("should return 401 for missing token", () => {
    authMiddleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      error: "Unauthorized",
      message: "No token provided",
    });
  });

  test("should return 401 for expired token", () => {
    const expiredAuth = new JWTAuth({
      secret: "test-secret-123",
      algorithm: "HS256",
      accessTokenExpiry: "-1s", // Expired 1 second ago
    });

    const expiredMiddleware = createAuthMiddleware(expiredAuth);
    const payload = { userId: "123" };
    const token = expiredAuth.generateAccessToken(payload);
    req.headers.authorization = `Bearer ${token}`;

    expiredMiddleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      error: "Unauthorized",
      message: "Token has expired",
      code: "TOKEN_EXPIRED",
    });
  });

  test("should return 401 for invalid token", () => {
    req.headers.authorization = "Bearer invalid.token.here";

    authMiddleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      error: "Unauthorized",
      message: "Invalid token",
      code: expect.any(String),
    });
  });
});

describe("Role Middleware", () => {
  let roleMiddleware;
  let req, res, next;

  beforeEach(() => {
    req = {
      user: null,
    };

    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    next = jest.fn();
  });

  test("should allow access for user with required role", () => {
    req.user = { roles: ["admin"] };
    roleMiddleware = createRoleMiddleware("admin");

    roleMiddleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  test("should allow access for user with one of required roles", () => {
    req.user = { roles: ["editor"] };
    roleMiddleware = createRoleMiddleware(["admin", "editor"]);

    roleMiddleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  test("should return 403 for user without required role", () => {
    req.user = { roles: ["user"] };
    roleMiddleware = createRoleMiddleware("admin");

    roleMiddleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({
      error: "Forbidden",
      message: "Insufficient permissions",
    });
  });

  test("should return 401 when no user information is present", () => {
    roleMiddleware = createRoleMiddleware("user");

    roleMiddleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      error: "Unauthorized",
      message: "No user information found",
    });
  });
});
