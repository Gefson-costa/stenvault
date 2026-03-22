/**
 * @stenvault/shared
 * Shared code between frontend (web) and backend (api)
 *
 * Exports:
 * - Types: error classes, timestamp types
 * - Constants: App constants
 * - Utils: error handling, formatting
 */

// Type exports
export * from "./types";
export * from "./types/timestamp";

// Constant exports
export * from "./const";

// Utility exports
export * from "./utils/format";
export * from "./utils/recoveryCode";

// Platform abstraction layer (crypto, storage, haptics)
export * from "./platform";

// Storage abstraction layer
export * from "./storage";

// Core business logic (transfer, streaming)
export * from "./core";

