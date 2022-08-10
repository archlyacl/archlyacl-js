/**
 * @module functions
 */
import { InvalidTypeError } from './errors';
import { Entity } from './types';

/**
 * Gets the ID of an object.
 *
 * Any object that meets one of the following conditions is accepted:
 *
 * - a string type
 * - has the `id` string/numberic property
 *
 * @param entity - The item to add to the registry.
 * @throws {InvalidTypeError} Throws this error if the supplied item does not meet any of the conditions.
 */
export function getValue(entity: Partial<Entity> | string): string {
  if (typeof entity === 'string') {
    return entity;
  }
  if (!entity.id) {
    throw new InvalidTypeError();
  }
  if (typeof entity.id === 'number') {
    return entity.id.toString();
  }
  return entity.id;
}
