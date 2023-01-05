import { describe, expect, test } from 'vitest';
import { Acl } from './acl';
import * as permission from './permission';

describe('Instantiation', () => {
  test(`Properties are initialized`, () => {
    const a1 = new Acl();

    const per = a1.exportPermissions();
    expect(permission.visualize(per)).toBe(`*--*
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
});
