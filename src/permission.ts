/**
 * @module permission
 */

import * as errors from './errors';
import { isTraceLevel2, isTraceLevel3, isTraceLevel4 } from './functions';
import { ROOT_ENTITY } from './types';

// Reference:  https://dev.to/hansott/how-to-check-if-string-is-member-of-union-type-1j4m
const ACCESS_TYPES = ['create', 'delete', 'read', 'update'];
type AccessTuple = typeof ACCESS_TYPES;
type AccessType = AccessTuple[number];

export type Access = {
  [K in AccessType]?: boolean;
};

export type AccessAllType = keyof Access | 'all';

export interface Chart {
  entries: Map<string, ChartEntry>;
}

export interface ChartEntry {
  access: Access;
  resource: string;
  role: string;
}

/**
 * Assigns a specific set of permissions on the resource to the role.
 *
 * @param chart - The Chart object.
 * @param role - The ID of the access request object.
 * @param resource - The ID of the access control object.
 * @param access - The access permissions.
 */
export function assign(
  chart: Chart,
  role: string,
  resource: string,
  access: Access
) {
  const key = _keyFromString(role, resource);
  let entry = chart.entries.get(key);
  if (entry) {
    if (isTraceLevel4()) {
      console.debug(
        `Changing "${prettyPrint(entry.access)}" to "${prettyPrint(
          access
        )}" for role "${role}" and resource "${resource}".`
      );
    }
    entry.access = access;
    chart.entries.set(key, entry);
    return entry;
  }
  entry = {
    access,
    role,
    resource,
  };
  if (isTraceLevel4()) {
    console.debug(
      `Adding "${prettyPrint(
        entry.access
      )}" for role "${role}" and resource "${resource}".`
    );
  }
  chart.entries.set(key, entry);
  return entry;
}

/**
 * Removes all permission assignments.
 *
 * @param chart - The Chart object.
 */
export function clear(chart: Chart) {
  chart.entries.clear();
}

/**
 * Clones the chart as a Map instance for exporting.
 *
 * @param chart - The Chart object.
 */
export function clone(chart: Chart): Map<string, ChartEntry> {
  return new Map(chart.entries);
}

/**
 * Gets the set of unique resources in the chart.
 *
 * @param chart - The Chart object.
 */
export function getResources(chart: Chart): Set<string> {
  const data = new Set<string>();
  for (const ent of chart.entries.values()) {
    data.add(ent.resource);
  }
  return data;
}

/**
 * Gets the set of unique roles in the chart.
 *
 * @param chart - The Chart object.
 */
export function getRoles(chart: Chart): Set<string> {
  const data = new Set<string>();
  for (const ent of chart.entries.values()) {
    data.add(ent.role);
  }
  return data;
}

/**
 * Determines if the role-resource tuple is present.
 *
 * @param chart - The Chart object.
 * @param role - The ID of the access request object.
 * @param resource - The ID of the access control object.
 */
export function hasEntities(
  chart: Chart,
  role: string,
  resource: string
): boolean {
  if (chart.entries.get(_keyFromString(role, resource))) {
    return true;
  }
  return false;
}

/**
 * Checks if ALL access is false.
 *
 * @param a - The Access object to check.
 */
export function isAccessAllFalse(a: Access): boolean {
  if (a.create !== false) {
    return false;
  }
  if (a.delete !== false) {
    return false;
  }
  if (a.read !== false) {
    return false;
  }
  if (a.update !== false) {
    return false;
  }
  return true;
}

/**
 * Checks if ALL access is true.
 *
 * @param a - The Access object to check.
 */
export function isAccessAllTrue(a: Access): boolean {
  if (!a.create) {
    return false;
  }
  if (!a.delete) {
    return false;
  }
  if (!a.read) {
    return false;
  }
  if (!a.update) {
    return false;
  }
  return true;
}

/**
 * Determines if the role has access on the resource.
 *
 * @param chart - The Chart object.
 * @param role - The ID of the access request object.
 * @param resource - The ID of the access control object.
 * @param accessType - The type of access to check for.
 */
export function isAllowed(
  chart: Chart,
  role: string,
  resource: string,
  accessType: AccessAllType
): boolean | null {
  const entry = chart.entries.get(_keyFromString(role, resource));
  if (!entry) {
    if (isTraceLevel2()) {
      console.debug(
        `Permission chart does not contain role "${role}" and resource "${resource}".`
      );
    }
    return null;
  }

  if (isTraceLevel4()) {
    console.debug(
      `Permission chart contains ${prettyPrint(
        entry.access
      )} for role "${role}" and resource "${resource}".`
    );
  }
  if (accessType === 'all') {
    return isAccessAllTrue(entry.access);
  }
  return entry.access[accessType] === true;
}

/**
 * Determines if the role is denied access on the resource.
 *
 * @param chart - The Chart object.
 * @param role - The ID of the access request object.
 * @param resource - The ID of the access control object.
 * @param accessType - The type of access to check for.
 */
export function isDenied(
  chart: Chart,
  role: string,
  resource: string,
  accessType: AccessAllType
): boolean | null {
  const entry = chart.entries.get(_keyFromString(role, resource));
  if (!entry) {
    if (isTraceLevel2()) {
      console.debug(
        `Permission chart does not contain role "${role}" and resource "${resource}".`
      );
    }
    return null;
  }

  if (isTraceLevel4()) {
    console.debug(
      `Permission chart contains ${prettyPrint(
        entry.access
      )} for role "${role}" and resource "${resource}".`
    );
  }
  if (accessType === 'all') {
    return isAccessAllFalse(entry.access);
  }
  return entry.access[accessType] === false;
}

/**
 * Creates an access object with all access granted.
 */
export function makeAccessAllowAll(): Access {
  return {
    create: true,
    delete: true,
    read: true,
    update: true,
  };
}

/**
 * Creates an access object with all access denied.
 */
export function makeAccessDenyAll(): Access {
  return {
    create: false,
    delete: false,
    read: false,
    update: false,
  };
}

/**
 * Modifies the Chart to have default access granted.
 *
 * @param chart - The Chart object.
 */
export function makeDefaultAccess(chart: Chart) {
  const ce: ChartEntry = {
    access: makeAccessAllowAll(),
    resource: ROOT_ENTITY,
    role: ROOT_ENTITY,
  };
  chart.entries.set(_keyFromEntry(ce), ce);
}

/**
 * Modifies the Chart to have default access denied.
 *
 * @param chart - The Chart object.
 */
export function makeDefaultDeny(chart: Chart) {
  const ce: ChartEntry = {
    access: makeAccessDenyAll(),
    resource: ROOT_ENTITY,
    role: ROOT_ENTITY,
  };
  chart.entries.set(_keyFromEntry(ce), ce);
}

/**
 * Re-creates the permission chart.
 *
 * @param from - The Map that is exported (cloned) previously.
 */
export function newFromClone(from: Map<string, ChartEntry>): Chart {
  return {
    entries: new Map(from),
  };
}

/**
 * Creates a new set of permissions.
 */
export function newPermissions(): Chart {
  return {
    entries: new Map<string, ChartEntry>(),
  };
}

/**
 * Removes a specific set of permissions on the resource from the role.
 *
 * @param chart - The Chart object.
 * @param role - The ID of the access request object.
 * @param resource - The ID of the access control object.
 * @param removeTypes - The types of access to remove.
 */
export function remove(
  chart: Chart,
  role: string,
  resource: string,
  removeTypes: AccessAllType[]
) {
  const key = _keyFromString(role, resource);
  if (isTraceLevel3()) {
    console.debug(`Remove "${removeTypes.join(', ')}" for ${key}.`);
  }
  let entry = chart.entries.get(key);
  if (!entry) {
    throw new errors.NotFoundError(`Permission "${key}" not in chart.`);
  }
  const newAccess = _subtract(entry.access, removeTypes);
  if (!newAccess) {
    if (isTraceLevel4()) {
      console.debug(`Remove entry ${key} from permissions chart.`);
    }
    chart.entries.delete(key);
    return null;
  }
  if (isTraceLevel4()) {
    console.debug(
      `Reducing "${prettyPrint(entry.access)}" to "${prettyPrint(
        newAccess
      )}" for ${key}`
    );
  }
  return entry;
}

/**
 * Removes a specific set of permissions on the resource for all roles.
 *
 * @param chart - The Chart object.
 * @param resource - The ID of the access control object.
 * @param removeTypes - The types of access to remove.
 */
export function removeByResource(
  chart: Chart,
  resource: string,
  removeTypes: AccessAllType[]
) {
  if (isTraceLevel3()) {
    console.debug(
      `Remove "${removeTypes.join(', ')}" for resource "${resource}".`
    );
  }
  for (const entry of chart.entries.values()) {
    if (entry.resource === resource) {
      remove(chart, entry.role, resource, removeTypes);
    }
  }
}

// export function removeByRole()

/**
 * The number of specified permissions.
 *
 * @param chart The Chart object.
 */
export function size(chart: Chart) {
  return chart.entries.size;
}

/**
 * Creates a human-friendly version of the access permissions.
 *
 * If all the permissions are true or false, returns either `ALL:true` or `ALL:false` respectively.
 *
 * Otherwise, the return value contains the keys `READ`, `CREATE`, `UPDATE` and `DELETE` in that order with values `true` or `false`.
 * @param acc - The access permissions.
 */
export function prettyPrint(acc: Access): string {
  if (acc.create && acc.delete && acc.read && acc.update) {
    return 'ALL:true';
  }
  if (
    acc.create === false &&
    acc.delete === false &&
    acc.read === false &&
    acc.update === false
  ) {
    return 'ALL:false';
  }
  const output = [];
  if (acc.read === false) {
    output.push('READ:false');
  } else if (acc.read === true) {
    output.push('READ:true');
  }
  if (acc.create === false) {
    output.push('CREATE:false');
  } else if (acc.create === true) {
    output.push('CREATE:true');
  }
  if (acc.update === false) {
    output.push('UPDATE:false');
  } else if (acc.update === true) {
    output.push('UPDATE:true');
  }
  if (acc.delete === false) {
    output.push('DELETE:false');
  } else if (acc.delete === true) {
    output.push('DELETE:true');
  }
  return output.join(', ');
}

// Reference: https://bobbyhadz.com/blog/typescript-check-if-string-is-in-union-type
// function _isAccessAllType(s: string): s is AccessAllType {
//   if (s === 'all') {
//     return true;
//   }
//   if (ACCESS_TYPES.includes(s)) {
//     return true;
//   }
//   return false;
// }

function _keyFromEntry(ce: ChartEntry): string {
  return _keyFromString(ce.role, ce.resource);
}

function _keyFromString(aro: string, aco: string) {
  return `${aro}--${aco}`;
}

function _subtract(from: Access, types: AccessAllType[]): Access | null {
  if (types.includes('all')) {
    return null;
  }
  const access: Access = {};
  for (const [k, v] of Object.entries(from)) {
    if (!types.includes(k)) {
      access[k] = v;
    }
  }
  return access;
}
