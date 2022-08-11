import { describe, expect, test } from 'vitest';
import { DuplicateError, NotFoundError } from './errors';
import * as r from './registry';
import { ROOT_ENTITY } from './types';

describe('Single level', () => {
  const reg: r.Registry = {
    records: {},
    register: {},
  };
  const e1 = { id: 'e1' };
  const e2 = { id: 'e2' };
  const e3 = { id: 'e3' };
  const e4 = { id: 'e4' };

  test('Add/Remove entries', () => {
    expect(r.size(reg)).toBe(0);

    r.add(reg, e1);
    expect(r.size(reg)).toBe(1);
    expect(r.printAll(reg)).toBe(` e1 | *
`);

    // Cannot have duplicate entries.
    expect(() => {
      r.add(reg, e1);
    }).toThrow(DuplicateError);

    r.add(reg, e2);
    r.add(reg, e3);
    r.add(reg, e4);
    expect(r.size(reg)).toBe(4);
    expect(r.printAll(reg)).toBe(` e1 | *
 e2 | *
 e3 | *
 e4 | *
`);

    const removed = r.remove(reg, e1);
    expect(r.size(reg)).toBe(3);
    expect(r.printAll(reg)).toBe(` e2 | *
 e3 | *
 e4 | *
`);
    expect(removed.length).toBe(1);
    expect(removed[0]).toEqual({ id: 'e1' });

    // Cannot remove nonexistent entries.
    expect(() => {
      r.remove(reg, e1);
    }).toThrow(NotFoundError);
  });

  test('Clone/Clear/Import/Traverse', () => {
    const clone = r.clone(reg);
    expect(clone).toEqual({
      records: {
        e2: {
          id: 'e2',
        },
        e3: {
          id: 'e3',
        },
        e4: {
          id: 'e4',
        },
      },
      register: {
        e2: ROOT_ENTITY,
        e3: ROOT_ENTITY,
        e4: ROOT_ENTITY,
      },
    });

    expect(r.getChildIds(reg, e2)).toEqual([]);
    expect(r.getChildIds(reg, ROOT_ENTITY)).toEqual(['e2', 'e3', 'e4']);
    expect(r.getRecord(reg, 'e2')).toEqual({ id: 'e2' });
    expect(r.has(reg, e2)).toBe(true);
    expect(r.has(reg, e1)).toBe(false);
    expect(r.hasChild(reg, e2)).toBe(false);
    expect(r.hasChild(reg, e1)).toBe(false);

    r.clear(reg);
    expect(reg.records).toEqual({});
    expect(reg.register).toEqual({});

    const regi = r.recreate(clone);

    expect(r.size(regi)).toBe(3);
    expect(r.printAll(regi)).toBe(` e2 | *
 e3 | *
 e4 | *
`);

    expect(r.traverseToRoot(regi, e2)).toEqual(['e2', ROOT_ENTITY]);
  });
});

describe('2-levels', () => {
  const reg: r.Registry = {
    records: {},
    register: {},
  };

  const e1 = { id: 'e1' };
  const e2 = { id: 'e2' };
  const e3 = { id: 'e3' };
  const e1a = { id: 'e1a' };
  const e2a = { id: 'e2a' };
  const e2b = { id: 'e2b' };
  const e1a1 = { id: 'e1a1' };
  const e2a1 = { id: 'e2a1' };
  const e3a = { id: 'e3a' };
  const e3b = { id: 'e3b' };

  test('Add entries', () => {
    // 1st level.
    r.add(reg, e1);
    r.add(reg, e2);
    r.add(reg, e3);
    expect(r.size(reg)).toBe(3);
    expect(r.printAll(reg)).toBe(` e1 | *
 e2 | *
 e3 | *
`);

    // 2nd level.
    r.add(reg, e1a, e1);
    r.add(reg, e2a, e2);
    r.add(reg, e2b, e2);
    r.add(reg, e3a, e3);
    r.add(reg, e3b, e3);
    expect(r.size(reg)).toBe(8);
    expect(r.printAll(reg)).toBe(`  e1 | *
  e2 | *
  e3 | *
 e1a | e1
 e2a | e2
 e2b | e2
 e3a | e3
 e3b | e3
`);

    // Cannot have duplicate children.
    expect(() => {
      r.add(reg, e1a, e1);
    }).toThrow(DuplicateError);

    // Cannot add under nonexistent parent.
    expect(() => {
      r.add(reg, e2a1, e1a1);
    }).toThrow(NotFoundError);
  });

  test('Remove entries', () => {
    expect(r.size(reg)).toBe(8);

    let removed = r.remove(reg, e1, false);
    expect(removed.length).toBe(1);
    expect(removed).toEqual([{ id: 'e1' }]);
    expect(r.printAll(reg)).toBe(`  e2 | *
  e3 | *
 e1a | *
 e2a | e2
 e2b | e2
 e3a | e3
 e3b | e3
`);

    removed = r.remove(reg, e2, false);
    expect(removed.length).toBe(1);
    expect(removed).toEqual([{ id: 'e2' }]);
    expect(r.printAll(reg)).toBe(`  e3 | *
 e1a | *
 e2a | *
 e2b | *
 e3a | e3
 e3b | e3
`);

    removed = r.remove(reg, e3, true);
    expect(removed.length).toBe(3);
    expect(removed).toEqual([{ id: 'e3a' }, { id: 'e3b' }, { id: 'e3' }]);
    expect(r.printAll(reg)).toBe(` e1a | *
 e2a | *
 e2b | *
`);

    removed = r.remove(reg, e2a);
    expect(removed.length).toBe(1);
    expect(removed).toEqual([{ id: 'e2a' }]);
    expect(r.printAll(reg)).toBe(` e1a | *
 e2b | *
`);
  });
});
