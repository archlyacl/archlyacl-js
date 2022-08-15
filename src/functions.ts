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
export function getValue(entity: Partial<Entity>): string {
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

export function isTraceLevel1(): boolean {
  if (!process.env.ARCHLY_TRACE_LEVEL) {
    return false;
  }
  const n = parseInt(process.env.ARCHLY_TRACE_LEVEL, 10);
  if (isNaN(n)) {
    return false;
  }
  return n === 1;
}

export function isTraceLevel2(): boolean {
  if (!process.env.ARCHLY_TRACE_LEVEL) {
    return false;
  }
  const n = parseInt(process.env.ARCHLY_TRACE_LEVEL, 10);
  if (isNaN(n)) {
    return false;
  }
  return n <= 2 && n > 0;
}

export function isTraceLevel3(): boolean {
  if (!process.env.ARCHLY_TRACE_LEVEL) {
    return false;
  }
  const n = parseInt(process.env.ARCHLY_TRACE_LEVEL, 10);
  if (isNaN(n)) {
    return false;
  }
  return n <= 3 && n > 0;
}

export function isTraceLevel4(): boolean {
  if (!process.env.ARCHLY_TRACE_LEVEL) {
    return false;
  }
  const n = parseInt(process.env.ARCHLY_TRACE_LEVEL, 10);
  if (isNaN(n)) {
    return false;
  }
  return n <= 4 && n > 0;
}
