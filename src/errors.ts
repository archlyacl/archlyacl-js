/**
 * @module errors
 */

/**
 * Describes an error when the entity is already present in the registry.
 */
export class DuplicateError extends Error {
  constructor(id: string) {
    super(`Entity "${id}" already present in registry.`);
  }
}

/**
 * Describes an invalid type.
 */
export class InvalidTypeError extends Error {
  constructor(message?: string) {
    super(message);
  }
}

/**
 * Describes an error when the entity is not found in the registry.
 */
export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
  }
}
