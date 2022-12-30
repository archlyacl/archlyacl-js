import {
  beforeAll,
  afterAll,
  afterEach,
  describe,
  expect,
  test,
  vi,
} from 'vitest';

import * as errors from './errors';
import * as permission from './permission';
import { ROOT_ENTITY } from './types';

describe('Access checks', () => {
  test('isAccessAllFalse', () => {
    const a1: permission.Access = {};

    expect(permission.isAccessAllFalse(a1)).toBe(false);
    a1.create = false;
    expect(permission.isAccessAllFalse(a1)).toBe(false);
    a1.delete = false;
    expect(permission.isAccessAllFalse(a1)).toBe(false);
    a1.read = false;
    expect(permission.isAccessAllFalse(a1)).toBe(false);
    a1.update = false;
    expect(permission.isAccessAllFalse(a1)).toBe(true);
  });

  test('isAccessAllTrue', () => {
    const a1: permission.Access = {};

    expect(permission.isAccessAllTrue(a1)).toBe(false);
    a1.create = true;
    expect(permission.isAccessAllTrue(a1)).toBe(false);
    a1.delete = true;
    expect(permission.isAccessAllTrue(a1)).toBe(false);
    a1.read = true;
    expect(permission.isAccessAllTrue(a1)).toBe(false);
    a1.update = true;
    expect(permission.isAccessAllTrue(a1)).toBe(true);
  });
});

describe('Basic assignment of allow & deny', () => {
  test('Permissions not set yet', () => {
    const p = permission.newPermissions();
    const re1 = 'resource-1';
    const ro1 = 'role-1';

    expect(permission.isAllowed(p, ro1, re1, 'all')).toBeNull();
    expect(permission.isDenied(p, ro1, re1, 'all')).toBeNull();

    expect(permission.isAllowed(p, ro1, re1, 'create')).toBeNull();
    expect(permission.isDenied(p, ro1, re1, 'create')).toBeNull();
  });

  test('Default permissions', () => {
    const p = permission.newPermissions();
    const re0 = ROOT_ENTITY;
    const re1 = 'resource-1';
    const ro0 = ROOT_ENTITY;
    const ro1 = 'role-1';

    permission.makeDefaultAccess(p);
    expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
    expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
    expect(permission.isAllowed(p, ro0, re1, 'all')).toBeNull();
    expect(permission.isDenied(p, ro0, re1, 'all')).toBeNull();
    expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
    expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
    expect(permission.isAllowed(p, ro1, re1, 'all')).toBeNull();
    expect(permission.isDenied(p, ro1, re1, 'all')).toBeNull();

    expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
    expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
    expect(permission.isAllowed(p, ro0, re1, 'create')).toBeNull();
    expect(permission.isDenied(p, ro0, re1, 'create')).toBeNull();
    expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
    expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
    expect(permission.isAllowed(p, ro1, re1, 'create')).toBeNull();
    expect(permission.isDenied(p, ro1, re1, 'create')).toBeNull();

    permission.makeDefaultDeny(p);
    expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(false);
    expect(permission.isDenied(p, ro0, re0, 'all')).toBe(true);
    expect(permission.isAllowed(p, ro0, re1, 'all')).toBeNull();
    expect(permission.isDenied(p, ro0, re1, 'all')).toBeNull();
    expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
    expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
    expect(permission.isAllowed(p, ro1, re1, 'all')).toBeNull();
    expect(permission.isDenied(p, ro1, re1, 'all')).toBeNull();

    expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(false);
    expect(permission.isDenied(p, ro0, re0, 'create')).toBe(true);
    expect(permission.isAllowed(p, ro0, re1, 'create')).toBeNull();
    expect(permission.isDenied(p, ro0, re1, 'create')).toBeNull();
    expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
    expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
    expect(permission.isAllowed(p, ro1, re1, 'create')).toBeNull();
    expect(permission.isDenied(p, ro1, re1, 'create')).toBeNull();
  });

  describe('BA2: allow() all permissions with default allow', () => {
    const p = permission.newPermissions();
    const re0 = ROOT_ENTITY;
    const re1 = 'resource-1';
    const ro0 = ROOT_ENTITY;
    const ro1 = 'role-1';
    const accAll = permission.makeAccessAllowAll();

    test('default allow only', () => {
      permission.makeDefaultAccess(p);
      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re1, 'all')).toBeNull();

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re1, 'create')).toBeNull();
    });

    test('Allow ro1 on re1', () => {
      permission.assign(p, ro1, re1, accAll);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(true);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(false);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBe(true);
      expect(permission.isDenied(p, ro1, re1, 'create')).toBe(false);
    });

    test('Allow ro0 on re1', () => {
      permission.assign(p, ro0, re1, accAll);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re1, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(true);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(false);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re1, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBe(true);
      expect(permission.isDenied(p, ro1, re1, 'create')).toBe(false);
    });

    test('Allow ro1 on re0', () => {
      permission.assign(p, ro1, re0, accAll);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re1, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro1, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(true);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(false);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re1, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro1, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBe(true);
      expect(permission.isDenied(p, ro1, re1, 'create')).toBe(false);
    });
  });

  describe('allow() all permissions with default deny', () => {
    const p = permission.newPermissions();
    const re0 = ROOT_ENTITY;
    const re1 = 'resource-1';
    const ro0 = ROOT_ENTITY;
    const ro1 = 'role-1';
    const accAll = permission.makeAccessAllowAll();

    test('default deny only', () => {
      permission.makeDefaultDeny(p);
      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re1, 'all')).toBeNull();

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re1, 'create')).toBeNull();
    });

    test('Allow ro1 on re1', () => {
      permission.assign(p, ro1, re1, accAll);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(true);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(false);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBe(true);
      expect(permission.isDenied(p, ro1, re1, 'create')).toBe(false);
    });

    test('Allow ro0 on re1', () => {
      permission.assign(p, ro0, re1, accAll);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re1, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(true);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(false);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re1, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBe(true);
      expect(permission.isDenied(p, ro1, re1, 'create')).toBe(false);
    });

    test('Allow ro1 on re0', () => {
      permission.assign(p, ro1, re0, accAll);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re1, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro1, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(true);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(false);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re1, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro1, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBe(true);
      expect(permission.isDenied(p, ro1, re1, 'create')).toBe(false);
    });
  });

  describe('BA4: deny() all permissions with default allow', () => {
    const p = permission.newPermissions();
    const re0 = ROOT_ENTITY;
    const re1 = 'resource-1';
    const ro0 = ROOT_ENTITY;
    const ro1 = 'role-1';
    const accAll = permission.makeAccessDenyAll();

    test('default allow only', () => {
      permission.makeDefaultAccess(p);
      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re1, 'all')).toBeNull();

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re1, 'create')).toBeNull();
    });

    test('Deny ro1 on re1', () => {
      permission.assign(p, ro1, re1, accAll);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(true);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'create')).toBe(true);
    });

    test('Deny ro0 on re1', () => {
      permission.assign(p, ro0, re1, accAll);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBe(false);
      expect(permission.isDenied(p, ro0, re1, 'all')).toBe(true);
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(true);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBe(false);
      expect(permission.isDenied(p, ro0, re1, 'create')).toBe(true);
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'create')).toBe(true);
    });

    test('Deny ro1 on re0', () => {
      permission.assign(p, ro1, re0, accAll);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBe(false);
      expect(permission.isDenied(p, ro0, re1, 'all')).toBe(true);
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBe(false);
      expect(permission.isDenied(p, ro1, re0, 'all')).toBe(true);
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(true);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBe(false);
      expect(permission.isDenied(p, ro0, re1, 'create')).toBe(true);
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBe(false);
      expect(permission.isDenied(p, ro1, re0, 'create')).toBe(true);
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'create')).toBe(true);
    });
  });

  describe('deny() all permissions with default deny', () => {
    const p = permission.newPermissions();
    const re0 = ROOT_ENTITY;
    const re1 = 'resource-1';
    const ro0 = ROOT_ENTITY;
    const ro1 = 'role-1';
    const accAll = permission.makeAccessDenyAll();

    test('default deny only', () => {
      permission.makeDefaultDeny(p);
      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re1, 'all')).toBeNull();

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re1, 'create')).toBeNull();
    });

    test('Deny ro1 on re1', () => {
      permission.assign(p, ro1, re1, accAll);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(true);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'create')).toBe(true);
    });

    test('Deny ro0 on re1', () => {
      permission.assign(p, ro0, re1, accAll);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBe(false);
      expect(permission.isDenied(p, ro0, re1, 'all')).toBe(true);
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(true);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBe(false);
      expect(permission.isDenied(p, ro0, re1, 'create')).toBe(true);
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'create')).toBe(true);
    });

    test('Deny ro1 on re0', () => {
      permission.assign(p, ro1, re0, accAll);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBe(false);
      expect(permission.isDenied(p, ro0, re1, 'all')).toBe(true);
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBe(false);
      expect(permission.isDenied(p, ro1, re0, 'all')).toBe(true);
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(true);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBe(false);
      expect(permission.isDenied(p, ro0, re1, 'create')).toBe(true);
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBe(false);
      expect(permission.isDenied(p, ro1, re0, 'create')).toBe(true);
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'create')).toBe(true);
    });
  });
});

// The IDs in parentheses indicate the source that they are duplicated from.
describe('Removal of allow/deny', () => {
  describe('(BA2) allow() all permissions then remove()', () => {
    const p = permission.newPermissions();
    const re0 = ROOT_ENTITY;
    const re1 = 'resource-1';
    const ro0 = ROOT_ENTITY;
    const ro1 = 'role-1';
    const accAll = permission.makeAccessAllowAll();

    test('RA1: Default allow only', () => {
      permission.makeDefaultAccess(p);
      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re1, 'all')).toBeNull();

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re1, 'create')).toBeNull();
    });

    test('RA2: Allow ro1 on re1', () => {
      permission.assign(p, ro1, re1, accAll);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(true);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(false);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBe(true);
      expect(permission.isDenied(p, ro1, re1, 'create')).toBe(false);
    });

    test('RA3: Allow ro0 on re1', () => {
      permission.assign(p, ro0, re1, accAll);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re1, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(true);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(false);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re1, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBe(true);
      expect(permission.isDenied(p, ro1, re1, 'create')).toBe(false);
    });

    test('Allow ro1 on re0', () => {
      permission.assign(p, ro1, re0, accAll);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re1, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro1, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(true);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(false);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
    });
    //-- Whole section above duplicated from "BA2: allow() all permissions with default allow"

    test('(RA3) Remove ro1 on re0', () => {
      permission.remove(p, ro1, re0, ['all']);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re1, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(true);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(false);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re1, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBe(true);
      expect(permission.isDenied(p, ro1, re1, 'create')).toBe(false);
    });

    test('(RA2) Remove ro0 on re1', () => {
      permission.remove(p, ro0, re1, ['all']);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(true);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(false);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBe(true);
      expect(permission.isDenied(p, ro1, re1, 'create')).toBe(false);
    });

    test('(RA1) Remove ro1 on re1', () => {
      permission.remove(p, ro1, re1, ['all']);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re1, 'all')).toBeNull();

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re1, 'create')).toBeNull();
    });
  });

  describe('(BA4) deny() all permissions with default allow', () => {
    const p = permission.newPermissions();
    const re0 = ROOT_ENTITY;
    const re1 = 'resource-1';
    const ro0 = ROOT_ENTITY;
    const ro1 = 'role-1';
    const accAll = permission.makeAccessDenyAll();

    test('RD1: default allow only', () => {
      permission.makeDefaultAccess(p);
      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re1, 'all')).toBeNull();

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re1, 'create')).toBeNull();
    });

    test('RD2: Deny ro1 on re1', () => {
      permission.assign(p, ro1, re1, accAll);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(true);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'create')).toBe(true);
    });

    test('RD3: Deny ro0 on re1', () => {
      permission.assign(p, ro0, re1, accAll);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBe(false);
      expect(permission.isDenied(p, ro0, re1, 'all')).toBe(true);
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(true);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBe(false);
      expect(permission.isDenied(p, ro0, re1, 'create')).toBe(true);
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'create')).toBe(true);
    });

    test('Deny ro1 on re0', () => {
      permission.assign(p, ro1, re0, accAll);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBe(false);
      expect(permission.isDenied(p, ro0, re1, 'all')).toBe(true);
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBe(false);
      expect(permission.isDenied(p, ro1, re0, 'all')).toBe(true);
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(true);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBe(false);
      expect(permission.isDenied(p, ro0, re1, 'create')).toBe(true);
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBe(false);
      expect(permission.isDenied(p, ro1, re0, 'create')).toBe(true);
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'create')).toBe(true);
    });
    //-- Whole section above duplicated from "BA4: deny() all permissions with default allow"

    test('(RD3) Remove ro1 on re0', () => {
      permission.remove(p, ro1, re0, ['all']);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBe(false);
      expect(permission.isDenied(p, ro0, re1, 'all')).toBe(true);
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(true);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBe(false);
      expect(permission.isDenied(p, ro0, re1, 'create')).toBe(true);
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'create')).toBe(true);
    });

    test('(RD2) Remove ro0 on re1', () => {
      permission.remove(p, ro0, re1, ['all']);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(true);

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'create')).toBe(true);
    });

    test('(RD1) Remove ro1 on re1', () => {
      permission.remove(p, ro1, re1, ['all']);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re1, 'all')).toBeNull();

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re1, 'create')).toBeNull();
    });
  });
});

describe('Exceptions on removal', () => {
  const ro1 = 'role-1';
  const re1 = 'resource-1';
  describe('Removal of non-existing permissions', () => {
    test('Deny nonexistent ro1 on re1', () => {
      expect(() => {
        const p = permission.newPermissions();
        permission.remove(p, ro1, re1, ['all']);
      }).toThrow(errors.NotFoundError);
    });
  });
});

describe('Trace level outputs', () => {
  describe('Nonexistent entries', () => {
    afterAll(() => {
      process.env.ARCHLY_TRACE_LEVEL = undefined;
    });

    const p = permission.newPermissions();
    const ro1 = 'role-1';
    const re1 = 'resource-1';

    test('Trace level 2', () => {
      // Add `mockImplementation` to prevent the output from polluting the output.
      const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});
      process.env.ARCHLY_TRACE_LEVEL = '2';
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBeNull();
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy).toHaveBeenCalledWith(
        `Permission chart does not contain role "${ro1}" and resource "${re1}".`
      );
    });

    test('Trace level 4', () => {
      const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});
      process.env.ARCHLY_TRACE_LEVEL = '4';

      const accAll = permission.makeAccessDenyAll();
      permission.assign(p, ro1, re1, accAll);
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy).toHaveBeenCalledWith(
        `Adding "ALL:false" for role "${ro1}" and resource "${re1}".`
      );

      expect(permission.isAllowed(p, ro1, re1, 'all'));
      expect(spy).toHaveBeenCalledTimes(2);
      expect(spy).toHaveBeenLastCalledWith(
        `Permission chart contains ALL:false for role "${ro1}" and resource "${re1}".`
      );

      const accNoCreate = permission.makeAccessAllowAll();
      accNoCreate.create = false;
      permission.assign(p, ro1, re1, accNoCreate);
      expect(spy).toHaveBeenCalledTimes(3);
      expect(spy).toHaveBeenLastCalledWith(
        `Changing "ALL:false" to "READ:true, CREATE:false, UPDATE:true, DELETE:true" for role "${ro1}" and resource "${re1}".`
      );
    });
  });

  describe('`assign` function', () => {
    describe('No trace level set', () => {
      beforeAll(() => {
        process.env.ARCHLY_TRACE_LEVEL = undefined;
      });
      afterEach(() => {
        vi.restoreAllMocks();
      });

      const p = permission.newPermissions();
      const ro1 = 'role-1';
      const re1 = 'resource-1';
      const accAllAllow = permission.makeAccessAllowAll();
      const accAllDeny = permission.makeAccessDenyAll();

      permission.makeDefaultAccess(p);

      const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});

      test(`First assign`, () => {
        let entry = permission.assign(p, ro1, re1, accAllAllow);
        expect(spy).toHaveBeenCalledTimes(0);
        expect(entry).toEqual({
          access: {
            create: true,
            delete: true,
            read: true,
            update: true,
          },
          role: ro1,
          resource: re1,
        });
      });

      test('Subsequent assign', () => {
        let entry = permission.assign(p, ro1, re1, accAllDeny);
        expect(spy).toHaveBeenCalledTimes(0);
        expect(entry).toEqual({
          access: {
            create: false,
            delete: false,
            read: false,
            update: false,
          },
          role: ro1,
          resource: re1,
        });
      });
    });

    describe('Trace level 4', () => {
      beforeAll(() => {
        process.env.ARCHLY_TRACE_LEVEL = '4';
      });
      afterEach(() => {
        vi.restoreAllMocks();
      });
      afterAll(() => {
        process.env.ARCHLY_TRACE_LEVEL = undefined;
      });

      const p = permission.newPermissions();
      const ro1 = 'role-1';
      const re1 = 'resource-1';
      const accAllAllow = permission.makeAccessAllowAll();
      const accAllDeny = permission.makeAccessDenyAll();

      permission.makeDefaultAccess(p);

      test(`First assign`, () => {
        const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});
        let entry = permission.assign(p, ro1, re1, accAllAllow);
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy).toHaveBeenCalledWith(
          `Adding "ALL:true" for role "${ro1}" and resource "${re1}".`
        );
        expect(entry).toEqual({
          access: {
            create: true,
            delete: true,
            read: true,
            update: true,
          },
          role: ro1,
          resource: re1,
        });
      });

      test('Subsequent assign', () => {
        const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});
        let entry = permission.assign(p, ro1, re1, accAllDeny);
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy).toHaveBeenLastCalledWith(
          `Changing "ALL:true" to "ALL:false" for role "${ro1}" and resource "${re1}".`
        );
        expect(entry).toEqual({
          access: {
            create: false,
            delete: false,
            read: false,
            update: false,
          },
          role: ro1,
          resource: re1,
        });
      });
    });
  });
});

describe('Code coverage', () => {
  test('Cloning and clearing', () => {
    const p = permission.newPermissions();
    const ro1 = 'role-1';
    const re1 = 'resource-1';
    const accAll = permission.makeAccessAllowAll();

    expect(permission.hasEntities(p, ro1, re1)).toBe(false);
    expect(permission.getRoles(p).size).toBe(0);
    expect(permission.getResources(p).size).toBe(0);

    permission.makeDefaultDeny(p);
    expect(permission.hasEntities(p, ro1, re1)).toBe(false);
    expect(permission.getRoles(p).size).toBe(1);
    expect(permission.getResources(p).size).toBe(1);

    permission.assign(p, ro1, re1, accAll);
    expect(permission.hasEntities(p, ro1, re1)).toBe(true);
    expect(permission.getRoles(p).size).toBe(2);
    expect(permission.getResources(p).size).toBe(2);

    const data = permission.clone(p);
    const clone = permission.newFromClone(data);
    expect(permission.hasEntities(clone, ro1, re1)).toBe(true);
    expect(permission.getRoles(clone).size).toBe(2);
    expect(permission.getResources(clone).size).toBe(2);

    permission.clear(p);
    expect(permission.hasEntities(p, ro1, re1)).toBe(false);
    expect(permission.getRoles(p).size).toBe(0);
    expect(permission.getResources(p).size).toBe(0);
  });
});
