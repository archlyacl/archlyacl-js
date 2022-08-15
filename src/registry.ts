/**
 * @module registry
 */

import * as errors from './errors';
import { getValue } from './functions';
import { Entity, ROOT_ENTITY } from './types';

/**
 * The registry for resources and roles.
 *
 * Contains `registry` to hold the hierarchy relationship and `records` to hold the original object.
 *
 * `records` are not used for evaluation of permissions - only to hold the original data.
 */
export interface Registry {
  records: Record<string, Entity>;
  register: Record<string, string>;
}

/**
 * Adds an entity to the registry.
 *
 * @param reg - The Registry object to add the entity to.
 * @param entity - The entity to add.
 * @param parent - The parent entry under which to place the entity.
 */
export function add(reg: Registry, entity: Entity, parent?: Entity) {
  const entityId = getValue(entity);
  if (has(reg, entity)) {
    throw new errors.DuplicateError(entityId);
  }
  if (!parent) {
    reg.register[entityId] = ROOT_ENTITY;
    if (typeof entity === 'string') {
      reg.records[entityId] = entity;
    } else {
      reg.records[entityId] = Object.assign({}, entity);
    }
    return;
  }

  const parentId = getValue(parent);
  if (!has(reg, parent)) {
    throw new errors.NotFoundError(`Entity "${parentId}" not in registry.`);
  }
  reg.register[entityId] = parentId;
  if (typeof entity === 'string') {
    reg.records[entityId] = entity;
  } else {
    reg.records[entityId] = Object.assign({}, entity);
  }
}

/**
 * Clears the registry.
 *
 * @param reg - The Registry object to clear.
 */
export function clear(reg: Registry) {
  reg.records = {};
  reg.register = {};
}

/**
 * Clones the registry for exporting.
 *
 * @param reg - The Registry object to clone.
 */
export function clone(reg: Registry): Registry {
  const records: Record<string, Entity> = {};
  const register: Record<string, string> = {};

  for (const k in reg.records) {
    if (typeof reg.records[k] === 'string') {
      records[k] = reg.records[k];
    } else {
      records[k] = Object.assign({}, reg.records[k]);
    }
  }

  for (const k in reg.register) {
    register[k] = reg.register[k];
  }

  return {
    records,
    register,
  };
}

/**
 * Gets the IDs of the children entities under the supplied parent.
 *
 * @param reg - The Registry object to traverse to get the child entities.
 * @param parent - The parent entity to get the children for.
 */
export function getChildIds(reg: Registry, parent: Entity | string): string[] {
  const children: string[] = [];
  const parentId = getValue(parent);

  for (const k in reg.register) {
    if (reg.register[k] === parentId) {
      children.push(k);
    }
  }
  return children;
}

/**
 * Gets the simple object from the registry.
 *
 * @param reg - The Registry object to get the entity from.
 * @param entityId - The ID of the entity to retrieve from the records.
 */
export function getRecord(reg: Registry, entityId: string): Entity {
  return reg.records[entityId];
}

/**
 * Checks whether an entity is in the registry.
 *
 * @param registry - The Registry object to check against.
 * @param entity - The entity to check for.
 */
export function has(reg: Registry, entity: Entity): boolean {
  const id = getValue(entity);
  return id in reg.register;
}

/**
 * Checks if there are children under the supplied parent entity.
 *
 * @param reg - The Registry object to check against.
 * @param parent - The parent entity to check for.
 * @returns Also returns false if the parent entity does not exist in the registry.
 */
export function hasChild(reg: Registry, parent: Entity): boolean {
  const parentId = getValue(parent);
  for (const child in reg.register) {
    if (reg.register[child] === parentId) {
      return true;
    }
  }
  return false;
}

/**
 * Prints a cascading list of entries in the registry.
 *
 * @param reg - The Registry object to print.
 * @param starting - The entity to start printing from.
 * @param lead - The leading space.
 */
export function print(
  reg: Registry,
  starting: Entity,
  lead: string = ''
): string {
  const output: string[] = [`${lead}- ${getValue(starting)}\n`];

  const children = getChildIds(reg, starting);
  children.forEach((child) => {
    output.push(print(reg, getRecord(reg, child), lead + '  '));
  });
  return output.join('');
}

export function printAll(reg: Registry): string {
  const output = [];
  let maxKeyLen = 0;

  // Get the maximum length from the keys.
  for (const k in reg.register) {
    if (maxKeyLen < k.length) {
      maxKeyLen = k.length;
    }
  }

  for (const [key, value] of Object.entries(reg.register)) {
    // Add the spaces in front.
    let empties = maxKeyLen - key.length;
    for (let i = 0; i <= empties; i++) {
      // <= to add 1 more.
      output.push(' ');
    }

    output.push(key);
    output.push(' | ');
    output.push(value);
    output.push('\n');
  }

  return output.join('');
}

/**
 * Re-creates the registry with a new hierarchy.
 *
 * @param from - The object with the keys `records` and `register` to import.
 * @throws {InvalidTypeError} Throws this error if the supplied argument does not contain either `records` or `register` as objects.
 */
export function recreate(from: Record<'records' | 'register', any>): Registry {
  const reg: Registry = {
    records: {},
    register: {},
  };
  if (typeof from.records !== 'object') {
    throw new errors.InvalidTypeError(
      `Import object does not contain \`records\` as an object.`
    );
  }
  if (typeof from.register !== 'object') {
    throw new errors.InvalidTypeError(
      `Import object does not contain \`register\` as an object.`
    );
  }

  for (const k in from.records) {
    if (typeof from.records[k] === 'string') {
      reg.records[k] = from.records[k];
    } else {
      reg.records[k] = Object.assign({}, from.records[k]);
    }
  }
  for (const k in from.register) {
    reg.register[k] = from.register[k];
  }
  return reg;
}

/**
 * Removes an entity and, optionally, its descendants from the registry.
 *
 * @param reg - The Registry object to remove the entity from.
 * @param entity - The entity to remove.
 * @param descendantsToo - If true, the descendants of the entity are removed as well.
 */
export function remove(
  reg: Registry,
  entity: Entity,
  descendantsToo: boolean = false
) {
  const removed: Entity[] = [];
  const entityId = getValue(entity);
  if (!has(reg, entity)) {
    throw new errors.NotFoundError(`Entity "${entityId}" not in registry.`);
  }
  if (hasChild(reg, entity)) {
    let parentId = reg.register[entityId];
    let childIds = getChildIds(reg, entity);

    if (descendantsToo) {
      childIds.forEach((childId: string) => {
        const child = getRecord(reg, childId);
        removed.push(...remove(reg, child, descendantsToo));
      });
    } else {
      // Change the parent of the descendants to the parent of the removed entity.
      childIds.forEach((childId: string) => {
        reg.register[childId] = parentId;
      });
    }
  }

  delete reg.register[entityId];
  delete reg.records[entityId];
  removed.push(entity);

  return removed;
}

/**
 * Gets the number of entries in the registry.
 *
 * @param reg - The Registry to count.
 */
export function size(reg: Registry): number {
  return Object.keys(reg.register).length;
}

/**
 * Creates a traversal path from the entry to the root of the hierarchy.
 *
 * @param reg - The Registry object to perform the traversal on.
 * @param entity - The entity to start traversing from.
 */
export function traverseToRoot(reg: Registry, entity: Entity): string[] {
  const path = [];

  let entityId = getValue(entity);
  while (entityId in reg.register) {
    path.push(entityId);
    entityId = reg.register[entityId]; // Get the parent.
  }
  path.push(ROOT_ENTITY);
  return path;
}
