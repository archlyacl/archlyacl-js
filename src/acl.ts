import { DuplicateError } from './errors';
import { getValue } from './functions';
import * as permission from './permission';
import * as registry from './registry';
import { Access, ActionAllType, Entity } from './types';

export class Acl {
  private permissions: permission.Chart;
  private resources: registry.Registry;
  private roles: registry.Registry;

  /**
   * Creates an instance of the Acl class.
   *
   * @param defaultAllow - Whether to have the default permission to be allowed or denied. If not specified, the default permission is not created.
   */
  constructor(defaultAllow?: boolean) {
    this.permissions = permission.newPermissions();
    if (defaultAllow) {
      permission.makeDefaultAccess(this.permissions);
    } else if (defaultAllow === false) {
      permission.makeDefaultDeny(this.permissions);
    }

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
   * @throws {DuplicateError} Throws this error if the resource is already present.
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
   * @throws {DuplicateError} Throws this error if the role is already present.
   * @throws {NotFoundError} Throws this error if the parent role, when specified, is not present in the registry.
   */
  public addRole(role: Entity, parent?: Entity) {
    registry.add(this.roles, role, parent);
  }

  public assign(role: Entity, resource: Entity, access: Access | boolean) {
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

    let ac: Access;
    if (access === true) {
      ac = permission.makeAccessAllowAll();
    } else if (access === false) {
      ac = permission.makeAccessDenyAll();
    } else {
      ac = access;
    }

    permission.assign(this.permissions, getValue(role), getValue(resource), ac);
  }

  /**
   * Clears the entire list.
   */
  public clear() {
    permission.clear(this.permissions);
    registry.clear(this.resources);
    registry.clear(this.roles);
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
   * Checks if the resource is in the registry.
   *
   * @param resource - The resource to check for.
   */
  public hasResource(resource: Entity): boolean {
    return registry.has(this.resources, resource);
  }

  /**
   * Checks if the role is in the registry.
   *
   * @param role - The role to check for.
   */
  public hasRole(role: Entity): boolean {
    return registry.has(this.roles, role);
  }

  /**
   * Checks if the role has the action access allowed for the specified resource.
   *
   * @param role - The role to check for.
   * @param resource - The resource to check for.
   * @param action - The action type. Default 'all'.
   */
  public isAllowed(
    role: Entity,
    resource: Entity,
    action: ActionAllType = 'all'
  ): boolean {
    const resPath = registry.traverseToRoot(this.resources, resource);
    const rolPath = registry.traverseToRoot(this.roles, role);

    for (const aro of rolPath) {
      for (const aco of resPath) {
        let grant = permission.isAllowed(this.permissions, aro, aco, action);
        if (grant !== null) {
          return grant;
        }
        // Else access not defined. Continue.
      }
    }
    return false;
  }

  /**
   * Checks if the role has the action access denied for the specified resource.
   *
   * @param role - The role to check for.
   * @param resource - The resource to check for.
   * @param action - The action type. Default 'all'.
   */
  public isDenied(
    role: Entity,
    resource: Entity,
    action: ActionAllType = 'all'
  ): boolean {
    const resPath = registry.traverseToRoot(this.resources, resource);
    const rolPath = registry.traverseToRoot(this.roles, role);

    for (const aro of rolPath) {
      for (const aco of resPath) {
        let grant = permission.isDenied(this.permissions, aro, aco, action);
        if (grant !== null) {
          return grant;
        }
        // Else access not defined. Continue.
      }
    }
    return false;
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
