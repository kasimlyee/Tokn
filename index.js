// index.js - Main library entry point

// Core functionality
const { JWTAuth, JWTError } = require("./lib/core");

// Middleware
const {
  createAuthMiddleware,
  createRoleMiddleware,
} = require("./lib/middleware");

// Security utilities
const SecurityUtils = require("./lib/security");

// Storage
const TokenStorage = require("./lib/storage");

// Export all public API components
module.exports = {
  // Core classes
  JWTAuth,
  JWTError,

  // Middleware creators
  createAuthMiddleware,
  createRoleMiddleware,

  // Utilities
  SecurityUtils,

  // Storage
  TokenStorage,
};
