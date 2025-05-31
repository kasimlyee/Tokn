const { JWTAuth, JWTError } = require("./core");

function createAuthMiddleware(jwtAuth, options = {}) {
  return function jwtMiddleware(req, res, next) {
    const token = extractToken(req, options);

    if (!token) {
      return res.status(401).json({
        error: "Unauthorized",
        message: "No token provided",
      });
    }

    try {
      const payload = jwtAuth.verifyToken(token, {
        verifyIssuer: options.verifyIssuer !== false,
        verifyAudience: options.verifyAudience !== false,
      });

      req.user = payload;
      req.token = token;
      next();
    } catch (err) {
      if (err.code === "TOKEN_EXPIRED") {
        return res.status(401).json({
          error: "Unauthorized",
          message: "Token has expired",
          code: err.code,
        });
      }

      return res.status(401).json({
        error: "Unauthorized",
        message: "Invalid token",
        code: err.code || "INVALID_TOKEN",
      });
    }
  };
}

function extractToken(req, options) {
  // Check Authorization header first
  if (req.headers.authorization) {
    const parts = req.headers.authorization.split(" ");
    if (parts.length === 2 && parts[0].toLowerCase() === "bearer") {
      return parts[1];
    }
  }

  // Check cookies if enabled
  if (options.cookie && req.cookies && req.cookies[options.cookie.name]) {
    return req.cookies[options.cookie.name];
  }

  // Check query parameter if enabled
  if (options.queryParam && req.query[options.queryParam]) {
    return req.query[options.queryParam];
  }

  // Check body if enabled
  if (options.bodyField && req.body && req.body[options.bodyField]) {
    return req.body[options.bodyField];
  }

  return null;
}

function createRoleMiddleware(requiredRoles) {
  if (typeof requiredRoles === "string") {
    requiredRoles = [requiredRoles];
  }

  return function roleMiddleware(req, res, next) {
    if (!req.user) {
      return res.status(401).json({
        error: "Unauthorized",
        message: "No user information found",
      });
    }

    const userRoles = req.user.roles || [];
    const hasRole = requiredRoles.some((role) => userRoles.includes(role));

    if (!hasRole) {
      return res.status(403).json({
        error: "Forbidden",
        message: "Insufficient permissions",
      });
    }

    next();
  };
}

module.exports = {
  createAuthMiddleware,
  createRoleMiddleware,
};
