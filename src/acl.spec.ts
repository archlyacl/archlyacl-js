import { describe, expect, test } from 'vitest';

import { Acl } from './acl';
import * as errors from './errors';
import * as permission from './permission';
import { ROOT_ENTITY } from './types';

describe('Instantiation', () => {
  test(`Instantiation with no default permissions`, () => {
    const a1 = new Acl();

    const per = a1.exportPermissions();
    expect(permission.printAll(per)).toBe(``);

    const res = a1.exportResources();
    expect(res).toEqual({
      records: {},
      register: {},
    });

    const rol = a1.exportRoles();
    expect(rol).toEqual({
      records: {},
      register: {},
    });
  });

  test(`Instantiation with default allow`, () => {
    const a1 = new Acl(true);

    const per = a1.exportPermissions();
    expect(permission.printAll(per)).toBe(`*--*
  ALL:true`);

    const res = a1.exportResources();
    expect(res).toEqual({
      records: {},
      register: {},
    });

    const rol = a1.exportRoles();
    expect(rol).toEqual({
      records: {},
      register: {},
    });

    // Adding resources without permissions should adopt default.
    const re1 = 'res-1';
    const ro1 = 'rol-1';

    a1.addResource(re1);
    a1.addRole(ro1);
    expect(a1.isAllowed(ro1, re1)).toBe(true);
    expect(a1.isAllowed(ro1, re1, 'all')).toBe(true);
    expect(a1.isAllowed(ro1, re1, 'create')).toBe(true);
    expect(a1.isAllowed(ro1, re1, 'delete')).toBe(true);
    expect(a1.isAllowed(ro1, re1, 'read')).toBe(true);
    expect(a1.isAllowed(ro1, re1, 'update')).toBe(true);
    expect(a1.isDenied(ro1, re1)).toBe(false);
    expect(a1.isDenied(ro1, re1, 'create')).toBe(false);
    expect(a1.isDenied(ro1, re1, 'delete')).toBe(false);
    expect(a1.isDenied(ro1, re1, 'read')).toBe(false);
    expect(a1.isDenied(ro1, re1, 'update')).toBe(false);

    // Clear the default permissions.
    a1.clear();
    expect(a1.isAllowed(ro1, re1)).toBe(false);
    expect(a1.isAllowed(ro1, re1, 'all')).toBe(false);
    expect(a1.isAllowed(ro1, re1, 'create')).toBe(false);
    expect(a1.isAllowed(ro1, re1, 'delete')).toBe(false);
    expect(a1.isAllowed(ro1, re1, 'read')).toBe(false);
    expect(a1.isAllowed(ro1, re1, 'update')).toBe(false);
    expect(a1.isDenied(ro1, re1)).toBe(false);
    expect(a1.isDenied(ro1, re1, 'create')).toBe(false);
    expect(a1.isDenied(ro1, re1, 'delete')).toBe(false);
    expect(a1.isDenied(ro1, re1, 'read')).toBe(false);
    expect(a1.isDenied(ro1, re1, 'update')).toBe(false);
  });

  test(`Instantiation with default deny`, () => {
    const a1 = new Acl(false);

    const per = a1.exportPermissions();
    expect(permission.printAll(per)).toBe(`*--*
  ALL:false`);

    const res = a1.exportResources();
    expect(res).toEqual({
      records: {},
      register: {},
    });

    const rol = a1.exportRoles();
    expect(rol).toEqual({
      records: {},
      register: {},
    });

    // Adding resources without permissions should adopt default.
    const re1 = 'res-1';
    const ro1 = 'rol-1';

    a1.addResource(re1);
    a1.addRole(ro1);
    expect(a1.isAllowed(ro1, re1)).toBe(false);
    expect(a1.isAllowed(ro1, re1, 'all')).toBe(false);
    expect(a1.isAllowed(ro1, re1, 'create')).toBe(false);
    expect(a1.isAllowed(ro1, re1, 'delete')).toBe(false);
    expect(a1.isAllowed(ro1, re1, 'read')).toBe(false);
    expect(a1.isAllowed(ro1, re1, 'update')).toBe(false);
    expect(a1.isDenied(ro1, re1)).toBe(true);
    expect(a1.isDenied(ro1, re1, 'create')).toBe(true);
    expect(a1.isDenied(ro1, re1, 'delete')).toBe(true);
    expect(a1.isDenied(ro1, re1, 'read')).toBe(true);
    expect(a1.isDenied(ro1, re1, 'update')).toBe(true);

    // Clear the default permissions.
    a1.clear();
    expect(a1.isAllowed(ro1, re1)).toBe(false);
    expect(a1.isAllowed(ro1, re1, 'all')).toBe(false);
    expect(a1.isAllowed(ro1, re1, 'create')).toBe(false);
    expect(a1.isAllowed(ro1, re1, 'delete')).toBe(false);
    expect(a1.isAllowed(ro1, re1, 'read')).toBe(false);
    expect(a1.isAllowed(ro1, re1, 'update')).toBe(false);
    expect(a1.isDenied(ro1, re1)).toBe(false);
    expect(a1.isDenied(ro1, re1, 'create')).toBe(false);
    expect(a1.isDenied(ro1, re1, 'delete')).toBe(false);
    expect(a1.isDenied(ro1, re1, 'read')).toBe(false);
    expect(a1.isDenied(ro1, re1, 'update')).toBe(false);
  });

  test(`Adding & removing of role/resource`, () => {
    const a1 = new Acl();
    const res1 = 'res-1';
    const rol1 = 'rol-1';

    a1.addResource(res1);
    let res = a1.exportResources();
    expect(res).toEqual({
      records: {
        'res-1': res1,
      },
      register: {
        'res-1': '*',
      },
    });

    a1.addRole(rol1);
    let rol = a1.exportRoles();
    expect(rol).toEqual({
      records: {
        'rol-1': rol1,
      },
      register: {
        'rol-1': '*',
      },
    });

    a1.removeRole(rol1);
    rol = a1.exportRoles();
    expect(rol).toEqual({
      records: {},
      register: {},
    });

    a1.removeResource(res1);
    res = a1.exportRoles();
    expect(res).toEqual({
      records: {},
      register: {},
    });
  });

  test(`Add resource exception`, () => {
    const a1 = new Acl();
    const res1 = 'res1';
    const res2 = 'res2';

    expect(() => {
      a1.addResource(res2, res1);
    }).toThrow(errors.NotFoundError);

    expect(a1.addResource(res1)).toBeFalsy();
    expect(a1.hasResource(res1)).toBe(true);
    expect(a1.hasResource(res2)).toBe(false);

    expect(a1.addResource(res2, res1)).toBeFalsy();
    expect(a1.hasResource(res1)).toBe(true);
    expect(a1.hasResource(res2)).toBe(true);
  });

  test(`Add role exception`, () => {
    const a1 = new Acl();
    const rol1 = 'rol1';
    const rol2 = 'rol2';

    expect(() => {
      a1.addRole(rol2, rol1);
    }).toThrow(errors.NotFoundError);

    expect(a1.addRole(rol1)).toBeFalsy();
    expect(a1.hasRole(rol1)).toBe(true);
    expect(a1.hasRole(rol2)).toBe(false);

    expect(a1.addRole(rol2, rol1)).toBeFalsy();
    expect(a1.hasRole(rol1)).toBe(true);
    expect(a1.hasRole(rol2)).toBe(true);
  });
});

describe(`ACL2: Assign ALLOW permissions`, () => {
  const res1 = 'res-1';
  const rol1 = 'rol-1';
  const res2 = 'res-2';
  const rol2 = 'rol-2';

  describe(`A: no permission set`, () => {
    test(`1: entities not added`, () => {
      const a1 = new Acl();
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
    });

    test(`2: entities added with no permissions`, () => {
      const a1 = new Acl();
      a1.addResource(res1);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);

      a1.addRole(rol1);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
    });

    test(`3: permissions added with no entities`, () => {
      const a1 = new Acl();
      a1.assign(rol1, res1, true);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
    });

    test(`4: permissions added with pre-existing entities`, () => {
      const a1 = new Acl();
      a1.addResource(res1);
      a1.addRole(rol1);
      a1.assign(rol1, res1, true);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
    });

    test(`5: child entities added with no permissions`, () => {
      const a1 = new Acl();
      a1.addResource(res1);
      a1.addResource(res2, res1);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res2)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
      expect(a1.isDenied(rol1, res2)).toBe(false);

      a1.addRole(rol1);
      a1.addRole(rol2, rol1);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res2)).toBe(false);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol2, res1)).toBe(false);
      expect(a1.isAllowed(rol2, res2)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
      expect(a1.isDenied(rol1, res2)).toBe(false);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol2, res1)).toBe(false);
      expect(a1.isDenied(rol2, res2)).toBe(false);
    });

    test(`6: permissions on children entities`, () => {
      const a1 = new Acl();
      a1.addResource(res1);
      a1.addResource(res2, res1);
      a1.addRole(rol1);
      a1.addRole(rol2, rol1);
      a1.assign(rol2, res2, true);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res2)).toBe(false);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol2, res1)).toBe(false);
      expect(a1.isAllowed(rol2, res2)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
      expect(a1.isDenied(rol1, res2)).toBe(false);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol2, res1)).toBe(false);
      expect(a1.isDenied(rol2, res2)).toBe(false);
    });

    test(`7: permissions on parent entities`, () => {
      const a1 = new Acl();
      a1.assign(rol1, res1, true);
      a1.addResource(res2, res1);
      a1.addRole(rol2, rol1);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res2)).toBe(true);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol2, res1)).toBe(true);
      expect(a1.isAllowed(rol2, res2)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
      expect(a1.isDenied(rol1, res2)).toBe(false);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol2, res1)).toBe(false);
      expect(a1.isDenied(rol2, res2)).toBe(false);
    });

    test(`8: override permissions on child entities`, () => {
      const a1 = new Acl();
      a1.assign(rol1, res1, true);
      a1.addResource(res2, res1);
      a1.addRole(rol2, rol1);
      a1.assign(rol2, res2, false);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res2)).toBe(true);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol2, res1)).toBe(true);
      expect(a1.isAllowed(rol2, res2)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
      expect(a1.isDenied(rol1, res2)).toBe(false);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol2, res1)).toBe(false);
      expect(a1.isDenied(rol2, res2)).toBe(true);
    });
  });

  describe(`B: default deny`, () => {
    test(`1: entities not added`, () => {
      const a1 = new Acl(false);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(true);
    });

    test(`2: entities added with no permissions`, () => {
      const a1 = new Acl(false);
      a1.addResource(res1);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(true);

      a1.addRole(rol1);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(true);
    });

    test(`3: permissions added with no entities`, () => {
      const a1 = new Acl(false);
      a1.assign(rol1, res1, true);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(false);
    });

    test(`4: permissions added with pre-existing entities`, () => {
      const a1 = new Acl(false);
      a1.addResource(res1);
      a1.addRole(rol1);
      a1.assign(rol1, res1, true);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(false);
    });

    // CONTINUE
  });

  describe(`C: default allow`, () => {
    test(`1: entities not added`, () => {
      const a1 = new Acl(true);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
    });

    test(`2: entities added with no permissions`, () => {
      const a1 = new Acl(true);
      a1.addResource(res1);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);

      a1.addRole(rol1);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
    });

    test(`3: permissions added with no entities`, () => {
      const a1 = new Acl(true);
      a1.assign(rol1, res1, true);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
    });

    test(`4: permissions added with pre-existing entities`, () => {
      const a1 = new Acl(true);
      a1.addResource(res1);
      a1.addRole(rol1);
      a1.assign(rol1, res1, true);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
    });
  });
});
