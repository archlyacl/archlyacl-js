import { beforeAll, afterAll, describe, expect, test, vi } from 'vitest';

import * as errors from './errors';
import * as permission from './permission';
import { Access, ROOT_ENTITY } from './types';

describe('Access checks', () => {
  test('isAccessAllFalse', () => {
    const a1: Access = {};

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
    const a1: Access = {};

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

    test(`Change then delete specific permission`, () => {
      // Change `delete` to false.
      permission.assign(p, ro1, re1, {
        read: true,
        create: true,
        update: true,
        delete: false,
      });

      expect(permission.size(p)).toBe(4);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re1, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro1, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(false); // False because `delete` is changed.
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(false);

      expect(permission.isAllowed(p, ro0, re0, 'delete')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'delete')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'delete')).toBe(true);
      expect(permission.isDenied(p, ro0, re1, 'delete')).toBe(false);
      expect(permission.isAllowed(p, ro1, re0, 'delete')).toBe(true);
      expect(permission.isDenied(p, ro1, re0, 'delete')).toBe(false);
      expect(permission.isAllowed(p, ro1, re1, 'delete')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'delete')).toBe(true);

      // Then remove the permission on `delete`.
      permission.remove(p, ro1, re1, ['delete']);

      // Number of entries should remain the same.
      expect(permission.size(p)).toBe(4);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re1, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro1, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(false); // False because `delete` is removed.
      expect(permission.isDenied(p, ro1, re1, 'all')).toBe(false);

      expect(permission.isAllowed(p, ro0, re0, 'delete')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'delete')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'delete')).toBe(true);
      expect(permission.isDenied(p, ro0, re1, 'delete')).toBe(false);
      expect(permission.isAllowed(p, ro1, re0, 'delete')).toBe(true);
      expect(permission.isDenied(p, ro1, re0, 'delete')).toBe(false);
      expect(permission.isAllowed(p, ro1, re1, 'delete')).toBe(false);
      expect(permission.isDenied(p, ro1, re1, 'delete')).toBeNull();
    });

    // Then remove 'all' permission.
    test('(RA1) Remove ro1 on re1', () => {
      permission.remove(p, ro1, re1, ['all']);

      // Number of entries should reduce by 1.
      expect(permission.size(p)).toBe(3);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re1, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro1, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBeNull(); // Null because permission is removed.
      expect(permission.isDenied(p, ro1, re1, 'all')).toBeNull(); // Null because permission is removed.

      expect(permission.isAllowed(p, ro0, re0, 'delete')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'delete')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'delete')).toBe(true);
      expect(permission.isDenied(p, ro0, re1, 'delete')).toBe(false);
      expect(permission.isAllowed(p, ro1, re0, 'delete')).toBe(true);
      expect(permission.isDenied(p, ro1, re0, 'delete')).toBe(false);
      expect(permission.isAllowed(p, ro1, re1, 'delete')).toBeNull(); // Null because permission is removed.
      expect(permission.isDenied(p, ro1, re1, 'delete')).toBeNull(); // Null because permission is removed.
    });

    test('(RA2) Remove ro0 on re1', () => {
      permission.remove(p, ro0, re1, ['all']);

      // Number of entries should reduce by 1.
      expect(permission.size(p)).toBe(2);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBeNull(); // Null because permission is removed.
      expect(permission.isDenied(p, ro0, re1, 'all')).toBeNull(); // Null because permission is removed.
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro1, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re1, 'all')).toBeNull();

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBeNull(); // Null because permission is removed.
      expect(permission.isDenied(p, ro0, re1, 'create')).toBeNull(); // Null because permission is removed.
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro1, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro1, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro1, re1, 'create')).toBeNull();
    });

    test('(RA3) Remove ro1 on re0', () => {
      permission.remove(p, ro1, re0, ['all']);

      // Number of entries should reduce by 1.
      expect(permission.size(p)).toBe(1);

      expect(permission.isAllowed(p, ro0, re0, 'all')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'all')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'all')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'all')).toBeNull(); // Null because permission is removed.
      expect(permission.isDenied(p, ro1, re0, 'all')).toBeNull(); // Null because permission is removed.
      expect(permission.isAllowed(p, ro1, re1, 'all')).toBeNull();
      expect(permission.isDenied(p, ro1, re1, 'all')).toBeNull();

      expect(permission.isAllowed(p, ro0, re0, 'create')).toBe(true);
      expect(permission.isDenied(p, ro0, re0, 'create')).toBe(false);
      expect(permission.isAllowed(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isDenied(p, ro0, re1, 'create')).toBeNull();
      expect(permission.isAllowed(p, ro1, re0, 'create')).toBeNull(); // Null because permission is removed.
      expect(permission.isDenied(p, ro1, re0, 'create')).toBeNull(); // Null because permission is removed.
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

describe('Removal by resource', () => {
  describe(`Removal of ALLOW access`, () => {
    const p = permission.newPermissions();
    const re1 = 'resource-1';
    const re2 = 'resource-2';
    const re3 = 'resource-3';
    const ro1 = 'role-1';
    const ro2 = 'role-2';
    const ro3 = 'role-3';
    const accAllAllow = permission.makeAccessAllowAll();

    // Add the roles and resources.
    permission.makeDefaultAccess(p);
    permission.assign(p, ro1, re1, accAllAllow);
    permission.assign(p, ro2, re1, accAllAllow);
    permission.assign(p, ro3, re1, accAllAllow);
    permission.assign(p, ro1, re2, accAllAllow);
    permission.assign(p, ro2, re2, accAllAllow);
    permission.assign(p, ro3, re2, accAllAllow);
    permission.assign(p, ro1, re3, accAllAllow);
    permission.assign(p, ro2, re3, accAllAllow);
    permission.assign(p, ro3, re3, accAllAllow);

    test('Initial state', () => {
      expect(permission.size(p)).toBe(10);

      const output = permission.printAll(p);
      expect(output).toBe(`*--*
  ALL:true
role-1--resource-1
  ALL:true
role-2--resource-1
  ALL:true
role-3--resource-1
  ALL:true
role-1--resource-2
  ALL:true
role-2--resource-2
  ALL:true
role-3--resource-2
  ALL:true
role-1--resource-3
  ALL:true
role-2--resource-3
  ALL:true
role-3--resource-3
  ALL:true`);
    });

    test(`Removal of ALL access on ${re1}`, () => {
      permission.removeByResource(p, re1, ['all']);
      expect(permission.size(p)).toBe(7);

      const output = permission.printAll(p);
      expect(output).toBe(`*--*
  ALL:true
role-1--resource-2
  ALL:true
role-2--resource-2
  ALL:true
role-3--resource-2
  ALL:true
role-1--resource-3
  ALL:true
role-2--resource-3
  ALL:true
role-3--resource-3
  ALL:true`);
    });

    test(`Removal of UPDATE access on ${re2}`, () => {
      permission.removeByResource(p, re2, ['update']);
      expect(permission.size(p)).toBe(7); // Remains the same size.

      const output = permission.printAll(p);
      expect(output).toBe(`*--*
  ALL:true
role-1--resource-2
  READ:true, CREATE:true, DELETE:true
role-2--resource-2
  READ:true, CREATE:true, DELETE:true
role-3--resource-2
  READ:true, CREATE:true, DELETE:true
role-1--resource-3
  ALL:true
role-2--resource-3
  ALL:true
role-3--resource-3
  ALL:true`);
    });
  });

  describe(`Removal of DENY access`, () => {
    const p = permission.newPermissions();
    const re1 = 'resource-1';
    const re2 = 'resource-2';
    const re3 = 'resource-3';
    const ro1 = 'role-1';
    const ro2 = 'role-2';
    const ro3 = 'role-3';
    const accAllDeny = permission.makeAccessDenyAll();

    // Add the roles and resources.
    permission.makeDefaultAccess(p);
    permission.assign(p, ro1, re1, accAllDeny);
    permission.assign(p, ro2, re1, accAllDeny);
    permission.assign(p, ro3, re1, accAllDeny);
    permission.assign(p, ro1, re2, accAllDeny);
    permission.assign(p, ro2, re2, accAllDeny);
    permission.assign(p, ro3, re2, accAllDeny);
    permission.assign(p, ro1, re3, accAllDeny);
    permission.assign(p, ro2, re3, accAllDeny);
    permission.assign(p, ro3, re3, accAllDeny);

    test('Initial state', () => {
      expect(permission.size(p)).toBe(10);

      const output = permission.printAll(p);
      expect(output).toBe(`*--*
  ALL:true
role-1--resource-1
  ALL:false
role-2--resource-1
  ALL:false
role-3--resource-1
  ALL:false
role-1--resource-2
  ALL:false
role-2--resource-2
  ALL:false
role-3--resource-2
  ALL:false
role-1--resource-3
  ALL:false
role-2--resource-3
  ALL:false
role-3--resource-3
  ALL:false`);
    });

    test(`Removal of ALL access on ${re1}`, () => {
      permission.removeByResource(p, re1, ['all']);
      expect(permission.size(p)).toBe(7);

      const output = permission.printAll(p);
      expect(output).toBe(`*--*
  ALL:true
role-1--resource-2
  ALL:false
role-2--resource-2
  ALL:false
role-3--resource-2
  ALL:false
role-1--resource-3
  ALL:false
role-2--resource-3
  ALL:false
role-3--resource-3
  ALL:false`);
    });

    test(`Removal of UPDATE access on ${re2}`, () => {
      permission.removeByResource(p, re2, ['update']);
      expect(permission.size(p)).toBe(7); // Remains the same size.

      const output = permission.printAll(p);
      expect(output).toBe(`*--*
  ALL:true
role-1--resource-2
  READ:false, CREATE:false, DELETE:false
role-2--resource-2
  READ:false, CREATE:false, DELETE:false
role-3--resource-2
  READ:false, CREATE:false, DELETE:false
role-1--resource-3
  ALL:false
role-2--resource-3
  ALL:false
role-3--resource-3
  ALL:false`);
    });

    test(`Removal of READ and DELETE access on ${re2}`, () => {
      permission.removeByResource(p, re2, ['read', 'delete']);
      expect(permission.size(p)).toBe(7); // Remains the same size.

      const output = permission.printAll(p);
      expect(output).toBe(`*--*
  ALL:true
role-1--resource-2
  CREATE:false
role-2--resource-2
  CREATE:false
role-3--resource-2
  CREATE:false
role-1--resource-3
  ALL:false
role-2--resource-3
  ALL:false
role-3--resource-3
  ALL:false`);
    });

    test(`Removal of READ and ALL access on ${re3}`, () => {
      permission.removeByResource(p, re3, ['read', 'all']);
      expect(permission.size(p)).toBe(4);

      const output = permission.printAll(p);
      expect(output).toBe(`*--*
  ALL:true
role-1--resource-2
  CREATE:false
role-2--resource-2
  CREATE:false
role-3--resource-2
  CREATE:false`);
    });
  });
});

describe('Removal by role', () => {
  describe(`Removal of ALLOW access`, () => {
    const p = permission.newPermissions();
    const re1 = 'resource-1';
    const re2 = 'resource-2';
    const re3 = 'resource-3';
    const ro1 = 'role-1';
    const ro2 = 'role-2';
    const ro3 = 'role-3';
    const accAllAllow = permission.makeAccessAllowAll();

    // Add the roles and resources.
    permission.makeDefaultAccess(p);
    permission.assign(p, ro1, re1, accAllAllow);
    permission.assign(p, ro2, re1, accAllAllow);
    permission.assign(p, ro3, re1, accAllAllow);
    permission.assign(p, ro1, re2, accAllAllow);
    permission.assign(p, ro2, re2, accAllAllow);
    permission.assign(p, ro3, re2, accAllAllow);
    permission.assign(p, ro1, re3, accAllAllow);
    permission.assign(p, ro2, re3, accAllAllow);
    permission.assign(p, ro3, re3, accAllAllow);

    test('Initial state', () => {
      expect(permission.size(p)).toBe(10);

      const output = permission.printAll(p);
      expect(output).toBe(`*--*
  ALL:true
role-1--resource-1
  ALL:true
role-2--resource-1
  ALL:true
role-3--resource-1
  ALL:true
role-1--resource-2
  ALL:true
role-2--resource-2
  ALL:true
role-3--resource-2
  ALL:true
role-1--resource-3
  ALL:true
role-2--resource-3
  ALL:true
role-3--resource-3
  ALL:true`);
    });

    test(`Removal of ALL access of ${ro1}`, () => {
      permission.removeByRole(p, ro1, ['all']);
      expect(permission.size(p)).toBe(7);

      const output = permission.printAll(p);
      expect(output).toBe(`*--*
  ALL:true
role-2--resource-1
  ALL:true
role-3--resource-1
  ALL:true
role-2--resource-2
  ALL:true
role-3--resource-2
  ALL:true
role-2--resource-3
  ALL:true
role-3--resource-3
  ALL:true`);
    });

    test(`Removal of UPDATE access on ${ro2}`, () => {
      permission.removeByRole(p, ro2, ['update']);
      expect(permission.size(p)).toBe(7); // Remains the same size.

      const output = permission.printAll(p);
      expect(output).toBe(`*--*
  ALL:true
role-2--resource-1
  READ:true, CREATE:true, DELETE:true
role-3--resource-1
  ALL:true
role-2--resource-2
  READ:true, CREATE:true, DELETE:true
role-3--resource-2
  ALL:true
role-2--resource-3
  READ:true, CREATE:true, DELETE:true
role-3--resource-3
  ALL:true`);
    });

    test(`Removal of READ and DELETE access on ${ro2}`, () => {
      permission.removeByRole(p, ro2, ['read', 'delete']);
      expect(permission.size(p)).toBe(7); // Remains the same size.

      const output = permission.printAll(p);
      expect(output).toBe(`*--*
  ALL:true
role-2--resource-1
  CREATE:true
role-3--resource-1
  ALL:true
role-2--resource-2
  CREATE:true
role-3--resource-2
  ALL:true
role-2--resource-3
  CREATE:true
role-3--resource-3
  ALL:true`);
    });

    test(`Removal of READ and ALL access on ${ro3}`, () => {
      permission.removeByRole(p, ro3, ['read', 'all']);
      expect(permission.size(p)).toBe(4);

      const output = permission.printAll(p);
      expect(output).toBe(`*--*
  ALL:true
role-2--resource-1
  CREATE:true
role-2--resource-2
  CREATE:true
role-2--resource-3
  CREATE:true`);
    });
  });

  describe(`Removal of DENY access`, () => {
    const p = permission.newPermissions();
    const re1 = 'resource-1';
    const re2 = 'resource-2';
    const re3 = 'resource-3';
    const ro1 = 'role-1';
    const ro2 = 'role-2';
    const ro3 = 'role-3';
    const accAllDeny = permission.makeAccessDenyAll();

    // Add the roles and resources.
    permission.makeDefaultAccess(p);
    permission.assign(p, ro1, re1, accAllDeny);
    permission.assign(p, ro2, re1, accAllDeny);
    permission.assign(p, ro3, re1, accAllDeny);
    permission.assign(p, ro1, re2, accAllDeny);
    permission.assign(p, ro2, re2, accAllDeny);
    permission.assign(p, ro3, re2, accAllDeny);
    permission.assign(p, ro1, re3, accAllDeny);
    permission.assign(p, ro2, re3, accAllDeny);
    permission.assign(p, ro3, re3, accAllDeny);

    test('Initial state', () => {
      expect(permission.size(p)).toBe(10);

      const output = permission.printAll(p);
      expect(output).toBe(`*--*
  ALL:true
role-1--resource-1
  ALL:false
role-2--resource-1
  ALL:false
role-3--resource-1
  ALL:false
role-1--resource-2
  ALL:false
role-2--resource-2
  ALL:false
role-3--resource-2
  ALL:false
role-1--resource-3
  ALL:false
role-2--resource-3
  ALL:false
role-3--resource-3
  ALL:false`);
    });

    test(`Removal of ALL access on ${ro1}`, () => {
      permission.removeByRole(p, ro1, ['all']);
      expect(permission.size(p)).toBe(7);

      const output = permission.printAll(p);
      expect(output).toBe(`*--*
  ALL:true
role-2--resource-1
  ALL:false
role-3--resource-1
  ALL:false
role-2--resource-2
  ALL:false
role-3--resource-2
  ALL:false
role-2--resource-3
  ALL:false
role-3--resource-3
  ALL:false`);
    });

    test(`Removal of UPDATE access on ${ro2}`, () => {
      permission.removeByRole(p, ro2, ['update']);
      expect(permission.size(p)).toBe(7); // Remains the same size.

      const output = permission.printAll(p);
      expect(output).toBe(`*--*
  ALL:true
role-2--resource-1
  READ:false, CREATE:false, DELETE:false
role-3--resource-1
  ALL:false
role-2--resource-2
  READ:false, CREATE:false, DELETE:false
role-3--resource-2
  ALL:false
role-2--resource-3
  READ:false, CREATE:false, DELETE:false
role-3--resource-3
  ALL:false`);
    });
  });
});

describe('Trace level outputs', () => {
  describe('Nonexistent entries', () => {
    describe('Trace level 2', () => {
      beforeAll(() => {
        process.env.ARCHLY_TRACE_LEVEL = '2';
      });
      afterAll(() => {
        process.env.ARCHLY_TRACE_LEVEL = undefined;
      });

      const p = permission.newPermissions();
      const ro1 = 'role-1';
      const re1 = 'resource-1';

      test('isAllowed', () => {
        // Add `mockImplementation` to prevent the output from polluting the output.
        const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});

        expect(permission.isAllowed(p, ro1, re1, 'all')).toBeNull();
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy).toHaveBeenCalledWith(
          `Permission chart does not contain role "${ro1}" and resource "${re1}".`
        );
      });

      test('isDenied', () => {
        const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});
        expect(permission.isDenied(p, ro1, re1, 'all')).toBeNull();
        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy).toHaveBeenCalledWith(
          `Permission chart does not contain role "${ro1}" and resource "${re1}".`
        );
      });
    });
  });

  describe('`assign` function', () => {
    describe('No trace level set', () => {
      beforeAll(() => {
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
        const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});

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

        expect(permission.isAllowed(p, ro1, re1, 'all')).toBe(true);
        expect(spy).toHaveBeenCalledTimes(2);
        expect(spy).toHaveBeenLastCalledWith(
          `Permission chart contains ALL:true for role "${ro1}" and resource "${re1}".`
        );
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

        expect(permission.isDenied(p, ro1, re1, 'all')).toBe(true);
        expect(spy).toHaveBeenCalledTimes(2);
        expect(spy).toHaveBeenLastCalledWith(
          `Permission chart contains ALL:false for role "${ro1}" and resource "${re1}".`
        );
      });
    });
  });

  describe('`remove` function', () => {
    beforeAll(() => {
      process.env.ARCHLY_TRACE_LEVEL = '4';
    });
    afterAll(() => {
      process.env.ARCHLY_TRACE_LEVEL = undefined;
    });

    const ro1 = 'role-1';
    const re1 = 'resource-1';
    const accAllAllow = permission.makeAccessAllowAll();

    test('entry not found', () => {
      const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});
      expect(() => {
        const p = permission.newPermissions();
        permission.remove(p, ro1, re1, ['all']);
      }).toThrow(errors.NotFoundError);
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy).toHaveBeenCalledWith(`Remove "all" for ${ro1}--${re1}.`);
    });

    test('entry found - ALL access', () => {
      const p = permission.newPermissions();
      permission.assign(p, ro1, re1, accAllAllow);

      const spy = vi.spyOn(console, 'debug');
      let entry = permission.remove(p, ro1, re1, ['all']);
      expect(entry).toBeNull();
      expect(spy).toHaveBeenCalledTimes(2);
      expect(spy).toHaveBeenCalledWith(`Remove "all" for ${ro1}--${re1}.`);
    });

    test('entry found - DELETE access', () => {
      const p = permission.newPermissions();
      permission.assign(p, ro1, re1, accAllAllow);

      const spy = vi.spyOn(console, 'debug');
      let entry = permission.remove(p, ro1, re1, ['delete']);
      expect(entry).toEqual({
        access: {
          create: true,
          read: true,
          update: true,
        },
        role: ro1,
        resource: re1,
      });
      expect(spy).toHaveBeenCalledTimes(2);
      expect(spy).toHaveBeenCalledWith(`Remove "delete" for ${ro1}--${re1}.`);
      expect(spy).toHaveBeenCalledWith(
        `Reducing "ALL:true" to "READ:true, CREATE:true, UPDATE:true" for ${ro1}--${re1}`
      );
    });
  });

  describe('`removeBy` functions', () => {
    beforeAll(() => {
      process.env.ARCHLY_TRACE_LEVEL = '3';
    });
    afterAll(() => {
      process.env.ARCHLY_TRACE_LEVEL = undefined;
    });

    const ro1 = 'role-1';
    const re1 = 'resource-1';
    const accAllAllow = permission.makeAccessAllowAll();

    test('resource entries found', () => {
      const p = permission.newPermissions();
      permission.makeDefaultAccess(p);
      permission.assign(p, ro1, re1, accAllAllow);

      const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});
      permission.removeByResource(p, re1, ['all']);
      expect(spy).toHaveBeenCalledTimes(2);
      expect(spy).toHaveBeenCalledWith(`Remove "all" for resource "${re1}".`);
      expect(spy).toHaveBeenCalledWith(`Remove "all" for ${ro1}--${re1}.`);
    });

    test(`role entries found`, () => {
      const p = permission.newPermissions();
      permission.makeDefaultAccess(p);
      permission.assign(p, ro1, re1, accAllAllow);

      const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});
      permission.removeByRole(p, ro1, ['all']);
      expect(spy).toHaveBeenCalledTimes(2);
      expect(spy).toHaveBeenCalledWith(`Remove "all" for role "${ro1}".`);
      expect(spy).toHaveBeenCalledWith(`Remove "all" for ${ro1}--${re1}.`);
    });
  });
});

describe(`printAll`, () => {
  const ro1 = 'role-1';
  const re1 = 'resource-1';
  const ro2 = 'role-2';
  const re2 = 'resource-2';
  const accAllAllow = permission.makeAccessAllowAll();
  const accAllDeny = permission.makeAccessDenyAll();

  test(`Default ALL access`, () => {
    const p = permission.newPermissions();
    permission.makeDefaultAccess(p);
    const vis = permission.printAll(p);
    expect(vis).toBe(`*--*
  ALL:true`);
  });

  test(`Permissions with default access`, () => {
    const p = permission.newPermissions();
    permission.makeDefaultAccess(p);
    permission.assign(p, ro1, re1, accAllAllow);
    permission.assign(p, ro2, re2, {
      create: true,
      delete: false,
      read: true,
      update: false,
    });
    const vis = permission.printAll(p);
    expect(vis).toBe(`*--*
  ALL:true
role-1--resource-1
  ALL:true
role-2--resource-2
  READ:true, CREATE:true, UPDATE:false, DELETE:false`);
  });

  test(`Default ALL deny`, () => {
    const p = permission.newPermissions();
    permission.makeDefaultDeny(p);
    const vis = permission.printAll(p);
    expect(vis).toBe(`*--*
  ALL:false`);
  });

  test(`Permissions with default deny`, () => {
    const p = permission.newPermissions();
    permission.makeDefaultDeny(p);
    permission.assign(p, ro1, re1, accAllDeny);
    permission.assign(p, ro2, re2, {
      create: true,
      delete: false,
      read: true,
      update: false,
    });
    const vis = permission.printAll(p);
    expect(vis).toBe(`*--*
  ALL:false
role-1--resource-1
  ALL:false
role-2--resource-2
  READ:true, CREATE:true, UPDATE:false, DELETE:false`);
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

  test('prettyPrint', () => {
    const cases: { accesses: Access; be: string }[] = [
      {
        accesses: {
          create: true,
          delete: true,
          read: true,
          update: true,
        },
        be: 'ALL:true',
      },
      {
        accesses: {
          create: true,
          delete: true,
          read: false,
          update: true,
        },
        be: 'READ:false, CREATE:true, UPDATE:true, DELETE:true',
      },
      {
        accesses: {
          create: false,
          delete: true,
          read: false,
          update: true,
        },
        be: 'READ:false, CREATE:false, UPDATE:true, DELETE:true',
      },
      {
        accesses: {
          create: false,
          delete: true,
          read: false,
          update: false,
        },
        be: 'READ:false, CREATE:false, UPDATE:false, DELETE:true',
      },
      {
        accesses: {
          create: false,
          delete: false,
          read: false,
          update: false,
        },
        be: 'ALL:false',
      },
      {
        accesses: {
          create: false,
          delete: false,
          read: true,
          update: false,
        },
        be: 'READ:true, CREATE:false, UPDATE:false, DELETE:false',
      },
    ];

    for (const c of cases) {
      expect(permission.prettyPrint(c.accesses)).toBe(c.be);
    }
  });
});
