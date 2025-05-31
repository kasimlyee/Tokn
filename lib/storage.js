class TokenStorage {
  constructor(options = {}) {
    this.options = {
      storage: "memory",
      redis: null,
      ...options,
    };

    this.initStorage();
  }

  initStorage() {
    switch (this.options.storage) {
      case "memory":
        this.store = new Map();
        break;
      case "redis":
        if (!this.options.redis) {
          throw new Error("Redis client is required for redis storage");
        }
        this.store = this.options.redis;
        break;
      default:
        throw new Error(`Unsupported storage: ${this.options.storage}`);
    }
  }

  async set(key, value, ttl) {
    if (this.options.storage === "memory") {
      this.store.set(key, value);
      if (ttl) {
        setTimeout(() => this.store.delete(key), ttl).unref();
      }
      return true;
    } else if (this.options.storage === "redis") {
      return new Promise((resolve, reject) => {
        if (ttl) {
          this.store.setex(key, Math.ceil(ttl / 1000), value, (err, reply) => {
            if (err) reject(err);
            else resolve(reply);
          });
        } else {
          this.store.set(key, value, (err, reply) => {
            if (err) reject(err);
            else resolve(reply);
          });
        }
      });
    }
  }

  async get(key) {
    if (this.options.storage === "memory") {
      return this.store.get(key);
    } else if (this.options.storage === "redis") {
      return new Promise((resolve, reject) => {
        this.store.get(key, (err, reply) => {
          if (err) reject(err);
          else resolve(reply);
        });
      });
    }
  }

  async delete(key) {
    if (this.options.storage === "memory") {
      return this.store.delete(key);
    } else if (this.options.storage === "redis") {
      return new Promise((resolve, reject) => {
        this.store.del(key, (err, reply) => {
          if (err) reject(err);
          else resolve(reply);
        });
      });
    }
  }

  async has(key) {
    if (this.options.storage === "memory") {
      return this.store.has(key);
    } else if (this.options.storage === "redis") {
      return new Promise((resolve, reject) => {
        this.store.exists(key, (err, reply) => {
          if (err) reject(err);
          else resolve(reply === 1);
        });
      });
    }
  }
}

module.exports = TokenStorage;
