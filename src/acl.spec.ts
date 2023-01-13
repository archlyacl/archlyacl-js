import { describe, expect, test, vi } from 'vitest';

import { Acl } from './acl';
import * as errors from './errors';
import * as permission from './permission';
import { Access, ROOT_ENTITY } from './types';

describe('ACL1: Instantiation', () => {
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

    test(`9: override permissions on multiple levels`, () => {
      const res3 = 'res-3';
      const rol3 = 'rol-3';

      const a1 = new Acl();
      a1.addResource(res1);
      a1.addResource(res2, res1);
      a1.addResource(res3, res2);
      a1.addRole(rol1);
      a1.addRole(rol2, rol1);
      a1.addRole(rol3, rol2);
      // res1       rol1
      // └ res2     └ rol2
      // └ res3     └ rol3

      a1.assign(rol2, res1, false);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res2)).toBe(false);
      expect(a1.isAllowed(rol1, res3)).toBe(false);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol2, res1)).toBe(false);
      expect(a1.isAllowed(rol2, res2)).toBe(false);
      expect(a1.isAllowed(rol2, res3)).toBe(false);
      expect(a1.isAllowed(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol3, res1)).toBe(false);
      expect(a1.isAllowed(rol3, res2)).toBe(false);
      expect(a1.isAllowed(rol3, res3)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
      expect(a1.isDenied(rol1, res2)).toBe(false);
      expect(a1.isDenied(rol1, res3)).toBe(false);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol2, res1)).toBe(true);
      expect(a1.isDenied(rol2, res2)).toBe(true);
      expect(a1.isDenied(rol2, res3)).toBe(true);
      expect(a1.isDenied(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol3, res1)).toBe(true);
      expect(a1.isDenied(rol3, res2)).toBe(true);
      expect(a1.isDenied(rol3, res3)).toBe(true);

      a1.assign(rol2, res2, true);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res2)).toBe(false);
      expect(a1.isAllowed(rol1, res3)).toBe(false);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol2, res1)).toBe(false);
      expect(a1.isAllowed(rol2, res2)).toBe(true);
      expect(a1.isAllowed(rol2, res3)).toBe(true);
      expect(a1.isAllowed(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol3, res1)).toBe(false);
      expect(a1.isAllowed(rol3, res2)).toBe(true);
      expect(a1.isAllowed(rol3, res3)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
      expect(a1.isDenied(rol1, res2)).toBe(false);
      expect(a1.isDenied(rol1, res3)).toBe(false);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol2, res1)).toBe(true);
      expect(a1.isDenied(rol2, res2)).toBe(false);
      expect(a1.isDenied(rol2, res3)).toBe(false);
      expect(a1.isDenied(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol3, res1)).toBe(true);
      expect(a1.isDenied(rol3, res2)).toBe(false);
      expect(a1.isDenied(rol3, res3)).toBe(false);

      a1.assign(rol3, res3, false);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res2)).toBe(false);
      expect(a1.isAllowed(rol1, res3)).toBe(false);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol2, res1)).toBe(false);
      expect(a1.isAllowed(rol2, res2)).toBe(true);
      expect(a1.isAllowed(rol2, res3)).toBe(true);
      expect(a1.isAllowed(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol3, res1)).toBe(false);
      expect(a1.isAllowed(rol3, res2)).toBe(true);
      expect(a1.isAllowed(rol3, res3)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
      expect(a1.isDenied(rol1, res2)).toBe(false);
      expect(a1.isDenied(rol1, res3)).toBe(false);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol2, res1)).toBe(true);
      expect(a1.isDenied(rol2, res2)).toBe(false);
      expect(a1.isDenied(rol2, res3)).toBe(false);
      expect(a1.isDenied(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol3, res1)).toBe(true);
      expect(a1.isDenied(rol3, res2)).toBe(false);
      expect(a1.isDenied(rol3, res3)).toBe(true);
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

    test(`5: child entities added with no permissions`, () => {
      const a1 = new Acl(false);
      a1.addResource(res1);
      a1.addResource(res2, res1);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res2)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(true);
      expect(a1.isDenied(rol1, res2)).toBe(true);

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

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(true);
      expect(a1.isDenied(rol1, res2)).toBe(true);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol2, res1)).toBe(true);
      expect(a1.isDenied(rol2, res2)).toBe(true);
    });

    test(`6: permissions on children entities`, () => {
      const a1 = new Acl(false);
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

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(true);
      expect(a1.isDenied(rol1, res2)).toBe(true);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol2, res1)).toBe(true);
      expect(a1.isDenied(rol2, res2)).toBe(false);
    });

    test(`7: permissions on parent entities`, () => {
      const a1 = new Acl(false);
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

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(false);
      expect(a1.isDenied(rol1, res2)).toBe(false);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol2, res1)).toBe(false);
      expect(a1.isDenied(rol2, res2)).toBe(false);
    });

    test(`8: override permissions on child entities`, () => {
      const a1 = new Acl(false);
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

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(false);
      expect(a1.isDenied(rol1, res2)).toBe(false);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol2, res1)).toBe(false);
      expect(a1.isDenied(rol2, res2)).toBe(true);
    });

    test(`9: override permissions on multiple levels`, () => {
      const res3 = `res-3`;
      const rol3 = `rol-3`;

      const a1 = new Acl(false);
      a1.addResource(res1);
      a1.addResource(res2, res1);
      a1.addResource(res3, res2);
      a1.addRole(rol1);
      a1.addRole(rol2, rol1);
      a1.addRole(rol3, rol2);
      // res1       rol1
      // └ res2     └ rol2
      // └ res3     └ rol3

      a1.assign(rol2, res1, false);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res2)).toBe(false);
      expect(a1.isAllowed(rol1, res3)).toBe(false);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol2, res1)).toBe(false);
      expect(a1.isAllowed(rol2, res2)).toBe(false);
      expect(a1.isAllowed(rol2, res3)).toBe(false);
      expect(a1.isAllowed(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol3, res1)).toBe(false);
      expect(a1.isAllowed(rol3, res2)).toBe(false);
      expect(a1.isAllowed(rol3, res3)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res3)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(true);
      expect(a1.isDenied(rol1, res2)).toBe(true);
      expect(a1.isDenied(rol1, res3)).toBe(true);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol2, res1)).toBe(true);
      expect(a1.isDenied(rol2, res2)).toBe(true);
      expect(a1.isDenied(rol2, res3)).toBe(true);
      expect(a1.isDenied(rol3, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol3, res1)).toBe(true);
      expect(a1.isDenied(rol3, res2)).toBe(true);
      expect(a1.isDenied(rol3, res3)).toBe(true);

      a1.assign(rol2, res2, true);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res2)).toBe(false);
      expect(a1.isAllowed(rol1, res3)).toBe(false);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol2, res1)).toBe(false);
      expect(a1.isAllowed(rol2, res2)).toBe(true);
      expect(a1.isAllowed(rol2, res3)).toBe(true);
      expect(a1.isAllowed(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol3, res1)).toBe(false);
      expect(a1.isAllowed(rol3, res2)).toBe(true);
      expect(a1.isAllowed(rol3, res3)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res3)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(true);
      expect(a1.isDenied(rol1, res2)).toBe(true);
      expect(a1.isDenied(rol1, res3)).toBe(true);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol2, res1)).toBe(true);
      expect(a1.isDenied(rol2, res2)).toBe(false);
      expect(a1.isDenied(rol2, res3)).toBe(false);
      expect(a1.isDenied(rol3, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol3, res1)).toBe(true);
      expect(a1.isDenied(rol3, res2)).toBe(false);
      expect(a1.isDenied(rol3, res3)).toBe(false);

      a1.assign(rol3, res3, false);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res2)).toBe(false);
      expect(a1.isAllowed(rol1, res3)).toBe(false);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol2, res1)).toBe(false);
      expect(a1.isAllowed(rol2, res2)).toBe(true);
      expect(a1.isAllowed(rol2, res3)).toBe(true);
      expect(a1.isAllowed(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol3, res1)).toBe(false);
      expect(a1.isAllowed(rol3, res2)).toBe(true);
      expect(a1.isAllowed(rol3, res3)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res3)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(true);
      expect(a1.isDenied(rol1, res2)).toBe(true);
      expect(a1.isDenied(rol1, res3)).toBe(true);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol2, res1)).toBe(true);
      expect(a1.isDenied(rol2, res2)).toBe(false);
      expect(a1.isDenied(rol2, res3)).toBe(false);
      expect(a1.isDenied(rol3, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol3, res1)).toBe(true);
      expect(a1.isDenied(rol3, res2)).toBe(false);
      expect(a1.isDenied(rol3, res3)).toBe(true);
    });
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

    test(`5: child entities added with no permissions`, () => {
      const a1 = new Acl(true);
      a1.addResource(res1);
      a1.addResource(res2, res1);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res2)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
      expect(a1.isDenied(rol1, res2)).toBe(false);

      a1.addRole(rol1);
      a1.addRole(rol2, rol1);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res2)).toBe(true);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(true);
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

    test(`6: permissions on children entities`, () => {
      const a1 = new Acl(true);
      a1.addResource(res1);
      a1.addResource(res2, res1);
      a1.addRole(rol1);
      a1.addRole(rol2, rol1);
      a1.assign(rol2, res2, true);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res2)).toBe(true);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(true);
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

    test(`7: permissions on parent entities`, () => {
      const a1 = new Acl(true);
      a1.assign(rol1, res1, true);
      a1.addResource(res2, res1);
      a1.addRole(rol2, rol1);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res2)).toBe(true);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(true);
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
      const a1 = new Acl(true);
      a1.assign(rol1, res1, true);
      a1.addResource(res2, res1);
      a1.addRole(rol2, rol1);
      a1.assign(rol2, res2, false);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res2)).toBe(true);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(true);
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

    test(`9: override permissions on multiple levels`, () => {
      const res3 = `res-3`;
      const rol3 = `rol-3`;

      const a1 = new Acl(true);
      a1.addResource(res1);
      a1.addResource(res2, res1);
      a1.addResource(res3, res2);
      a1.addRole(rol1);
      a1.addRole(rol2, rol1);
      a1.addRole(rol3, rol2);
      // res1       rol1
      // └ res2     └ rol2
      // └ res3     └ rol3

      a1.assign(rol2, res1, false);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res3)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res2)).toBe(true);
      expect(a1.isAllowed(rol1, res3)).toBe(true);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol2, res1)).toBe(false);
      expect(a1.isAllowed(rol2, res2)).toBe(false);
      expect(a1.isAllowed(rol2, res3)).toBe(false);
      expect(a1.isAllowed(rol3, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol3, res1)).toBe(false);
      expect(a1.isAllowed(rol3, res2)).toBe(false);
      expect(a1.isAllowed(rol3, res3)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
      expect(a1.isDenied(rol1, res2)).toBe(false);
      expect(a1.isDenied(rol1, res3)).toBe(false);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol2, res1)).toBe(true);
      expect(a1.isDenied(rol2, res2)).toBe(true);
      expect(a1.isDenied(rol2, res3)).toBe(true);
      expect(a1.isDenied(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol3, res1)).toBe(true);
      expect(a1.isDenied(rol3, res2)).toBe(true);
      expect(a1.isDenied(rol3, res3)).toBe(true);

      a1.assign(rol2, res2, true);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res3)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res2)).toBe(true);
      expect(a1.isAllowed(rol1, res3)).toBe(true);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol2, res1)).toBe(false);
      expect(a1.isAllowed(rol2, res2)).toBe(true);
      expect(a1.isAllowed(rol2, res3)).toBe(true);
      expect(a1.isAllowed(rol3, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol3, res1)).toBe(false);
      expect(a1.isAllowed(rol3, res2)).toBe(true);
      expect(a1.isAllowed(rol3, res3)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
      expect(a1.isDenied(rol1, res2)).toBe(false);
      expect(a1.isDenied(rol1, res3)).toBe(false);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol2, res1)).toBe(true);
      expect(a1.isDenied(rol2, res2)).toBe(false);
      expect(a1.isDenied(rol2, res3)).toBe(false);
      expect(a1.isDenied(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol3, res1)).toBe(true);
      expect(a1.isDenied(rol3, res2)).toBe(false);
      expect(a1.isDenied(rol3, res3)).toBe(false);

      a1.assign(rol3, res3, false);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res3)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res2)).toBe(true);
      expect(a1.isAllowed(rol1, res3)).toBe(true);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol2, res1)).toBe(false);
      expect(a1.isAllowed(rol2, res2)).toBe(true);
      expect(a1.isAllowed(rol2, res3)).toBe(true);
      expect(a1.isAllowed(rol3, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol3, res1)).toBe(false);
      expect(a1.isAllowed(rol3, res2)).toBe(true);
      expect(a1.isAllowed(rol3, res3)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
      expect(a1.isDenied(rol1, res2)).toBe(false);
      expect(a1.isDenied(rol1, res3)).toBe(false);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol2, res1)).toBe(true);
      expect(a1.isDenied(rol2, res2)).toBe(false);
      expect(a1.isDenied(rol2, res3)).toBe(false);
      expect(a1.isDenied(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol3, res1)).toBe(true);
      expect(a1.isDenied(rol3, res2)).toBe(false);
      expect(a1.isDenied(rol3, res3)).toBe(true);
    });
  });
});

describe(`ACL3: Assign DENY permissions`, () => {
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
      a1.assign(rol1, res1, false);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(true);
    });

    test(`4: permissions added with pre-existing entities`, () => {
      const a1 = new Acl();
      a1.addResource(res1);
      a1.addRole(rol1);
      a1.assign(rol1, res1, false);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(true);
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
      a1.assign(rol2, res2, false);
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
      expect(a1.isDenied(rol2, res2)).toBe(true);
    });

    test(`7: permissions on parent entities`, () => {
      const a1 = new Acl();
      a1.assign(rol1, res1, false);
      a1.addResource(res2, res1);
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
      expect(a1.isDenied(rol1, res1)).toBe(true);
      expect(a1.isDenied(rol1, res2)).toBe(true);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol2, res1)).toBe(true);
      expect(a1.isDenied(rol2, res2)).toBe(true);
    });

    test(`8: override permissions on child entities`, () => {
      const a1 = new Acl();
      a1.assign(rol1, res1, false);
      a1.addResource(res2, res1);
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
      expect(a1.isDenied(rol1, res1)).toBe(true);
      expect(a1.isDenied(rol1, res2)).toBe(true);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol2, res1)).toBe(true);
      expect(a1.isDenied(rol2, res2)).toBe(false);
    });

    test(`9: override permissions on multiple levels`, () => {
      const res3 = 'res-3';
      const rol3 = 'rol-3';

      const a1 = new Acl();
      a1.addResource(res1);
      a1.addResource(res2, res1);
      a1.addResource(res3, res2);
      a1.addRole(rol1);
      a1.addRole(rol2, rol1);
      a1.addRole(rol3, rol2);
      // res1       rol1
      // └ res2     └ rol2
      // └ res3     └ rol3

      a1.assign(rol2, res1, true);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res2)).toBe(false);
      expect(a1.isAllowed(rol1, res3)).toBe(false);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol2, res1)).toBe(true);
      expect(a1.isAllowed(rol2, res2)).toBe(true);
      expect(a1.isAllowed(rol2, res3)).toBe(true);
      expect(a1.isAllowed(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol3, res1)).toBe(true);
      expect(a1.isAllowed(rol3, res2)).toBe(true);
      expect(a1.isAllowed(rol3, res3)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
      expect(a1.isDenied(rol1, res2)).toBe(false);
      expect(a1.isDenied(rol1, res3)).toBe(false);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol2, res1)).toBe(false);
      expect(a1.isDenied(rol2, res2)).toBe(false);
      expect(a1.isDenied(rol2, res3)).toBe(false);
      expect(a1.isDenied(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol3, res1)).toBe(false);
      expect(a1.isDenied(rol3, res2)).toBe(false);
      expect(a1.isDenied(rol3, res3)).toBe(false);

      a1.assign(rol2, res2, false);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res2)).toBe(false);
      expect(a1.isAllowed(rol1, res3)).toBe(false);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol2, res1)).toBe(true);
      expect(a1.isAllowed(rol2, res2)).toBe(false);
      expect(a1.isAllowed(rol2, res3)).toBe(false);
      expect(a1.isAllowed(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol3, res1)).toBe(true);
      expect(a1.isAllowed(rol3, res2)).toBe(false);
      expect(a1.isAllowed(rol3, res3)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
      expect(a1.isDenied(rol1, res2)).toBe(false);
      expect(a1.isDenied(rol1, res3)).toBe(false);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol2, res1)).toBe(false);
      expect(a1.isDenied(rol2, res2)).toBe(true);
      expect(a1.isDenied(rol2, res3)).toBe(true);
      expect(a1.isDenied(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol3, res1)).toBe(false);
      expect(a1.isDenied(rol3, res2)).toBe(true);
      expect(a1.isDenied(rol3, res3)).toBe(true);

      a1.assign(rol3, res3, true);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res2)).toBe(false);
      expect(a1.isAllowed(rol1, res3)).toBe(false);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol2, res1)).toBe(true);
      expect(a1.isAllowed(rol2, res2)).toBe(false);
      expect(a1.isAllowed(rol2, res3)).toBe(false);
      expect(a1.isAllowed(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol3, res1)).toBe(true);
      expect(a1.isAllowed(rol3, res2)).toBe(false);
      expect(a1.isAllowed(rol3, res3)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
      expect(a1.isDenied(rol1, res2)).toBe(false);
      expect(a1.isDenied(rol1, res3)).toBe(false);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol2, res1)).toBe(false);
      expect(a1.isDenied(rol2, res2)).toBe(true);
      expect(a1.isDenied(rol2, res3)).toBe(true);
      expect(a1.isDenied(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol3, res1)).toBe(false);
      expect(a1.isDenied(rol3, res2)).toBe(true);
      expect(a1.isDenied(rol3, res3)).toBe(false);
    });
  });

  describe('B: default deny', () => {
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
      a1.assign(rol1, res1, false);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(true);
    });

    test(`4: permissions added with pre-existing entities`, () => {
      const a1 = new Acl(false);
      a1.addResource(res1);
      a1.addRole(rol1);
      a1.assign(rol1, res1, false);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(true);
    });

    test(`5: child entities added with no permissions`, () => {
      const a1 = new Acl(false);
      a1.addResource(res1);
      a1.addResource(res2, res1);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res2)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(true);
      expect(a1.isDenied(rol1, res2)).toBe(true);

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

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(true);
      expect(a1.isDenied(rol1, res2)).toBe(true);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol2, res1)).toBe(true);
      expect(a1.isDenied(rol2, res2)).toBe(true);
    });

    test(`6: permissions on children entities`, () => {
      const a1 = new Acl(false);
      a1.addResource(res1);
      a1.addResource(res2, res1);
      a1.addRole(rol1);
      a1.addRole(rol2, rol1);
      a1.assign(rol2, res2, false);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res2)).toBe(false);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol2, res1)).toBe(false);
      expect(a1.isAllowed(rol2, res2)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(true);
      expect(a1.isDenied(rol1, res2)).toBe(true);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol2, res1)).toBe(true);
      expect(a1.isDenied(rol2, res2)).toBe(true);
    });

    test(`7: permissions on parent entities`, () => {
      const a1 = new Acl(false);
      a1.assign(rol1, res1, false);
      a1.addResource(res2, res1);
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

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(true);
      expect(a1.isDenied(rol1, res2)).toBe(true);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol2, res1)).toBe(true);
      expect(a1.isDenied(rol2, res2)).toBe(true);
    });

    test(`8: override permissions on child entities`, () => {
      const a1 = new Acl(false);
      a1.assign(rol1, res1, false);
      a1.addResource(res2, res1);
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

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(true);
      expect(a1.isDenied(rol1, res2)).toBe(true);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol2, res1)).toBe(true);
      expect(a1.isDenied(rol2, res2)).toBe(false);
    });

    test(`9: override permissions on multiple levels`, () => {
      const res3 = 'res-3';
      const rol3 = 'rol-3';

      const a1 = new Acl(false);
      a1.addResource(res1);
      a1.addResource(res2, res1);
      a1.addResource(res3, res2);
      a1.addRole(rol1);
      a1.addRole(rol2, rol1);
      a1.addRole(rol3, rol2);
      // res1       rol1
      // └ res2     └ rol2
      // └ res3     └ rol3

      a1.assign(rol2, res1, true);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res2)).toBe(false);
      expect(a1.isAllowed(rol1, res3)).toBe(false);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol2, res1)).toBe(true);
      expect(a1.isAllowed(rol2, res2)).toBe(true);
      expect(a1.isAllowed(rol2, res3)).toBe(true);
      expect(a1.isAllowed(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol3, res1)).toBe(true);
      expect(a1.isAllowed(rol3, res2)).toBe(true);
      expect(a1.isAllowed(rol3, res3)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res3)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(true);
      expect(a1.isDenied(rol1, res2)).toBe(true);
      expect(a1.isDenied(rol1, res3)).toBe(true);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol2, res1)).toBe(false);
      expect(a1.isDenied(rol2, res2)).toBe(false);
      expect(a1.isDenied(rol2, res3)).toBe(false);
      expect(a1.isDenied(rol3, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol3, res1)).toBe(false);
      expect(a1.isDenied(rol3, res2)).toBe(false);
      expect(a1.isDenied(rol3, res3)).toBe(false);

      a1.assign(rol2, res2, false);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res2)).toBe(false);
      expect(a1.isAllowed(rol1, res3)).toBe(false);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol2, res1)).toBe(true);
      expect(a1.isAllowed(rol2, res2)).toBe(false);
      expect(a1.isAllowed(rol2, res3)).toBe(false);
      expect(a1.isAllowed(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol3, res1)).toBe(true);
      expect(a1.isAllowed(rol3, res2)).toBe(false);
      expect(a1.isAllowed(rol3, res3)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res3)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(true);
      expect(a1.isDenied(rol1, res2)).toBe(true);
      expect(a1.isDenied(rol1, res3)).toBe(true);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol2, res1)).toBe(false);
      expect(a1.isDenied(rol2, res2)).toBe(true);
      expect(a1.isDenied(rol2, res3)).toBe(true);
      expect(a1.isDenied(rol3, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol3, res1)).toBe(false);
      expect(a1.isDenied(rol3, res2)).toBe(true);
      expect(a1.isDenied(rol3, res3)).toBe(true);

      a1.assign(rol3, res3, true);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isAllowed(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol1, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res2)).toBe(false);
      expect(a1.isAllowed(rol1, res3)).toBe(false);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol2, res1)).toBe(true);
      expect(a1.isAllowed(rol2, res2)).toBe(false);
      expect(a1.isAllowed(rol2, res3)).toBe(false);
      expect(a1.isAllowed(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isAllowed(rol3, res1)).toBe(true);
      expect(a1.isAllowed(rol3, res2)).toBe(false);
      expect(a1.isAllowed(rol3, res3)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isDenied(ROOT_ENTITY, res3)).toBe(true);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol1, res1)).toBe(true);
      expect(a1.isDenied(rol1, res2)).toBe(true);
      expect(a1.isDenied(rol1, res3)).toBe(true);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol2, res1)).toBe(false);
      expect(a1.isDenied(rol2, res2)).toBe(true);
      expect(a1.isDenied(rol2, res3)).toBe(true);
      expect(a1.isDenied(rol3, ROOT_ENTITY)).toBe(true);
      expect(a1.isDenied(rol3, res1)).toBe(false);
      expect(a1.isDenied(rol3, res2)).toBe(true);
      expect(a1.isDenied(rol3, res3)).toBe(false);
    });
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
      a1.assign(rol1, res1, false);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(true);
    });

    test(`4: permissions added with pre-existing entities`, () => {
      const a1 = new Acl(true);
      a1.addResource(res1);
      a1.addRole(rol1);
      a1.assign(rol1, res1, false);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(true);
    });

    test(`5: child entities added with no permissions`, () => {
      const a1 = new Acl(true);
      a1.addResource(res1);
      a1.addResource(res2, res1);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res2)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
      expect(a1.isDenied(rol1, res2)).toBe(false);

      a1.addRole(rol1);
      a1.addRole(rol2, rol1);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res2)).toBe(true);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(true);
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

    test(`6: permissions on children entities`, () => {
      const a1 = new Acl(true);
      a1.addResource(res1);
      a1.addResource(res2, res1);
      a1.addRole(rol1);
      a1.addRole(rol2, rol1);
      a1.assign(rol2, res2, false);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res2)).toBe(true);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(true);
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

    test(`7: permissions on parent entities`, () => {
      const a1 = new Acl(true);
      a1.assign(rol1, res1, false);
      a1.addResource(res2, res1);
      a1.addRole(rol2, rol1);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res2)).toBe(false);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol2, res1)).toBe(false);
      expect(a1.isAllowed(rol2, res2)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(true);
      expect(a1.isDenied(rol1, res2)).toBe(true);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol2, res1)).toBe(true);
      expect(a1.isDenied(rol2, res2)).toBe(true);
    });

    test(`8: override permissions on child entities`, () => {
      const a1 = new Acl(true);
      a1.assign(rol1, res1, false);
      a1.addResource(res2, res1);
      a1.addRole(rol2, rol1);
      a1.assign(rol2, res2, true);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(false);
      expect(a1.isAllowed(rol1, res2)).toBe(false);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol2, res1)).toBe(false);
      expect(a1.isAllowed(rol2, res2)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(true);
      expect(a1.isDenied(rol1, res2)).toBe(true);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol2, res1)).toBe(true);
      expect(a1.isDenied(rol2, res2)).toBe(false);
    });

    test(`9: override permissions on multiple levels`, () => {
      const res3 = 'res-3';
      const rol3 = 'rol-3';

      const a1 = new Acl(true);
      a1.addResource(res1);
      a1.addResource(res2, res1);
      a1.addResource(res3, res2);
      a1.addRole(rol1);
      a1.addRole(rol2, rol1);
      a1.addRole(rol3, rol2);
      // res1       rol1
      // └ res2     └ rol2
      // └ res3     └ rol3

      a1.assign(rol2, res1, true);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res3)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res2)).toBe(true);
      expect(a1.isAllowed(rol1, res3)).toBe(true);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol2, res1)).toBe(true);
      expect(a1.isAllowed(rol2, res2)).toBe(true);
      expect(a1.isAllowed(rol2, res3)).toBe(true);
      expect(a1.isAllowed(rol3, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol3, res1)).toBe(true);
      expect(a1.isAllowed(rol3, res2)).toBe(true);
      expect(a1.isAllowed(rol3, res3)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
      expect(a1.isDenied(rol1, res2)).toBe(false);
      expect(a1.isDenied(rol1, res3)).toBe(false);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol2, res1)).toBe(false);
      expect(a1.isDenied(rol2, res2)).toBe(false);
      expect(a1.isDenied(rol2, res3)).toBe(false);
      expect(a1.isDenied(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol3, res1)).toBe(false);
      expect(a1.isDenied(rol3, res2)).toBe(false);
      expect(a1.isDenied(rol3, res3)).toBe(false);

      a1.assign(rol2, res2, false);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res3)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res2)).toBe(true);
      expect(a1.isAllowed(rol1, res3)).toBe(true);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol2, res1)).toBe(true);
      expect(a1.isAllowed(rol2, res2)).toBe(false);
      expect(a1.isAllowed(rol2, res3)).toBe(false);
      expect(a1.isAllowed(rol3, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol3, res1)).toBe(true);
      expect(a1.isAllowed(rol3, res2)).toBe(false);
      expect(a1.isAllowed(rol3, res3)).toBe(false);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
      expect(a1.isDenied(rol1, res2)).toBe(false);
      expect(a1.isDenied(rol1, res3)).toBe(false);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol2, res1)).toBe(false);
      expect(a1.isDenied(rol2, res2)).toBe(true);
      expect(a1.isDenied(rol2, res3)).toBe(true);
      expect(a1.isDenied(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol3, res1)).toBe(false);
      expect(a1.isDenied(rol3, res2)).toBe(true);
      expect(a1.isDenied(rol3, res3)).toBe(true);

      a1.assign(rol3, res3, true);
      expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res2)).toBe(true);
      expect(a1.isAllowed(ROOT_ENTITY, res3)).toBe(true);
      expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol1, res1)).toBe(true);
      expect(a1.isAllowed(rol1, res2)).toBe(true);
      expect(a1.isAllowed(rol1, res3)).toBe(true);
      expect(a1.isAllowed(rol2, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol2, res1)).toBe(true);
      expect(a1.isAllowed(rol2, res2)).toBe(false);
      expect(a1.isAllowed(rol2, res3)).toBe(false);
      expect(a1.isAllowed(rol3, ROOT_ENTITY)).toBe(true);
      expect(a1.isAllowed(rol3, res1)).toBe(true);
      expect(a1.isAllowed(rol3, res2)).toBe(false);
      expect(a1.isAllowed(rol3, res3)).toBe(true);

      expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res2)).toBe(false);
      expect(a1.isDenied(ROOT_ENTITY, res3)).toBe(false);
      expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol1, res1)).toBe(false);
      expect(a1.isDenied(rol1, res2)).toBe(false);
      expect(a1.isDenied(rol1, res3)).toBe(false);
      expect(a1.isDenied(rol2, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol2, res1)).toBe(false);
      expect(a1.isDenied(rol2, res2)).toBe(true);
      expect(a1.isDenied(rol2, res3)).toBe(true);
      expect(a1.isDenied(rol3, ROOT_ENTITY)).toBe(false);
      expect(a1.isDenied(rol3, res1)).toBe(false);
      expect(a1.isDenied(rol3, res2)).toBe(true);
      expect(a1.isDenied(rol3, res3)).toBe(false);
    });
  });
});

describe(`ACL4: Additional coverage`, () => {
  const res1 = 'res-1';
  const rol1 = 'rol-1';

  test(`1: assign using Access object, and visualize`, () => {
    const acc: Access = {
      create: true,
      read: true,
      update: true,
      delete: true,
    };
    const a1 = new Acl();
    a1.assign(rol1, res1, acc);
    expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
    expect(a1.isAllowed(rol1, ROOT_ENTITY)).toBe(false);
    expect(a1.isAllowed(ROOT_ENTITY, res1)).toBe(false);
    expect(a1.isAllowed(rol1, res1)).toBe(true);

    expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
    expect(a1.isDenied(rol1, ROOT_ENTITY)).toBe(false);
    expect(a1.isDenied(ROOT_ENTITY, res1)).toBe(false);
    expect(a1.isDenied(rol1, res1)).toBe(false);

    expect(a1.visualize()).toBe(` res-1 | *

 rol-1 | *

rol-1--res-1
  ALL:true`);
  });

  test(`2: trace output for isAllowed`, () => {
    // Add `mockImplementation` to avoid polluting the output.
    const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});
    const a1 = new Acl();

    process.env.ARCHLY_TRACE_LEVEL = '3';
    expect(a1.isAllowed(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
    expect(spy).toHaveBeenCalledTimes(2);
    expect(spy).toHaveBeenCalledWith(`Checking role "*" on resource "*".`);
    expect(spy).toHaveBeenCalledWith(
      `Permission chart does not contain role "*" and resource "*".`
    );
    process.env.ARCHLY_TRACE_LEVEL = undefined;
  });

  test(`3: trace output for isDenied`, () => {
    // Add `mockImplementation` to avoid polluting the output.
    const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});
    const a1 = new Acl();

    process.env.ARCHLY_TRACE_LEVEL = '3';
    expect(a1.isDenied(ROOT_ENTITY, ROOT_ENTITY)).toBe(false);
    expect(spy).toHaveBeenCalledTimes(2);
    expect(spy).toHaveBeenCalledWith(`Checking role "*" on resource "*".`);
    expect(spy).toHaveBeenCalledWith(
      `Permission chart does not contain role "*" and resource "*".`
    );
    process.env.ARCHLY_TRACE_LEVEL = undefined;
  });
});
