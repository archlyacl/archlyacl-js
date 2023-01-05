import { DuplicateError } from './errors';
import { getValue } from './functions';
import * as permission from './permission';
import * as registry from './registry';
import { Access, Entity } from './types';

export class Acl {
  private permissions: permission.Chart;
  private resources: registry.Registry;
  private roles: registry.Registry;

  constructor() {
    this.permissions = permission.newPermissions();
    permission.makeDefaultAccess(this.permissions);

    this.resources = {
      records: {},
      register: {},
    };

    this.roles = {
      records: {},
      register: {},
    };
  }

  /**
   * Adds a resource to the resource registry.
   *
   * @param resource - The resource to add to the registry.
   * @param parent - The parent resource to add the new resource under. The parent resource must exist.
   * @throws {NotFoundError} Throws this error if the parent resource, when specified, is not present in the registry.
   */
  public addResource(resource: Entity, parent?: Entity) {
    registry.add(this.resources, resource, parent);
  }

  /**
   * Adds a role to the role registry.
   *
   * @param role - The role to add to the registry.
   * @param parent - The parent role to add the new role under. The parent role must exist.
   * @throws{NotFoundError} Throws this error if the parent resource, when specified, is not present in the registry.
   */
  public addRole(role: Entity, parent?: Entity) {
    registry.add(this.roles, role, parent);
  }

  public assign(role: Entity, resource: Entity, access: Access) {
    try {
      registry.add(this.resources, resource);
    } catch (e) {
      if (!(e instanceof DuplicateError)) {
        throw e;
      }
      // Else, do nothing.
    }

    try {
      registry.add(this.roles, role);
    } catch (e) {
      if (!(e instanceof DuplicateError)) {
        throw e;
      }
      // Else, do nothing.
    }

    permission.assign(
      this.permissions,
      getValue(role),
      getValue(resource),
      access
    );
  }

  /**
   * Exports the permissions Chart for saving to persistent storage.
   */
  public exportPermissions(): permission.Chart {
    return permission.newFromClone(permission.clone(this.permissions));
  }

  /**
   * Exports the resource registry for saving to persistent storage.
   */
  public exportResources(): registry.Registry {
    return registry.clone(this.resources);
  }

  /**
   * Exports the role registry for saving to persistent storage.
   */
  public exportRoles(): registry.Registry {
    return registry.clone(this.roles);
  }

  /**
   * Removes a resource and permissions related to it.
   *
   * @param resource - The resource to remove.
   * @param descendantsToo - Whether to remove resoures under the supplied resource as well. Default false.
   */
  public removeResource(resource: Entity, descendantsToo: boolean = false) {
    const resources = registry.remove(this.resources, resource, descendantsToo);
    for (const resource of resources) {
      permission.removeByResource(this.permissions, getValue(resource), [
        'all',
      ]);
    }
  }

  /**
   * Removes a role and permissions related to it.
   *
   * @param role - The role to remove.
   * @param descendantsToo - Whether to remove roles under the supplied role as well. Default false.
   */
  public removeRole(role: Entity, descendantsToo: boolean = false) {
    const roles = registry.remove(this.roles, role, descendantsToo);
    for (const role of roles) {
      permission.removeByRole(this.permissions, getValue(role), ['all']);
    }
  }
}
