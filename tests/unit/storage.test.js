const TokenStorage = require("../../lib/storage");
const mockRedis = require("mock-redis-client");

describe("Token Storage", () => {
  describe("Memory Storage", () => {
    let storage;

    beforeEach(() => {
      storage = new TokenStorage({ storage: "memory" });
    });

    test("should set and get value", async () => {
      await storage.set("key1", "value1");
      const value = await storage.get("key1");
      expect(value).toBe("value1");
    });

    test("should check if key exists", async () => {
      await storage.set("key2", "value2");
      expect(await storage.has("key2")).toBe(true);
      expect(await storage.has("nonexistent")).toBe(false);
    });

    test("should delete key", async () => {
      await storage.set("key3", "value3");
      await storage.delete("key3");
      expect(await storage.has("key3")).toBe(false);
    });

    test("should expire key after TTL", async () => {
      await storage.set("key4", "value4", 100); // 100ms TTL
      await new Promise((resolve) => setTimeout(resolve, 150));
      expect(await storage.has("key4")).toBe(false);
    });
  });

  describe("Redis Storage", () => {
    let storage;
    let mockClient;

    beforeEach(() => {
      mockClient = {
        setex: jest.fn((key, ttl, value, cb) => cb(null, "OK")),
        set: jest.fn((key, value, cb) => cb(null, "OK")),
        get: jest.fn((key, cb) => cb(null, "test-value")),
        del: jest.fn((key, cb) => cb(null, 1)),
        exists: jest.fn((key, cb) => cb(null, 1)),
        on: jest.fn(),
      };

      storage = new TokenStorage({
        storage: "redis",
        redis: mockClient,
      });
    });

    test("should set value with TTL", async () => {
      const result = await storage.set("key1", "value1", 1000);
      expect(result).toBe("OK");
      expect(mockClient.setex).toHaveBeenCalledWith(
        "key1",
        expect.any(Number),
        "value1",
        expect.any(Function)
      );
    });

    test("should set value without TTL", async () => {
      const result = await storage.set("key2", "value2");
      expect(result).toBe("OK");
      expect(mockClient.set).toHaveBeenCalledWith(
        "key2",
        "value2",
        expect.any(Function)
      );
    });

    test("should get value", async () => {
      const value = await storage.get("key3");
      expect(value).toBe("test-value");
      expect(mockClient.get).toHaveBeenCalledWith("key3", expect.any(Function));
    });

    test("should delete key", async () => {
      const result = await storage.delete("key4");
      expect(result).toBe(1);
      expect(mockClient.del).toHaveBeenCalledWith("key4", expect.any(Function));
    });

    test("should check if key exists", async () => {
      const exists = await storage.has("key5");
      expect(exists).toBe(true);
      expect(mockClient.exists).toHaveBeenCalledWith(
        "key5",
        expect.any(Function)
      );
    });
  });
});
