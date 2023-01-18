import { describe, expect, test } from 'vitest';
import { DuplicateError, InvalidTypeError, NotFoundError } from './errors';
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
});

describe('2 levels', () => {
  // Need to be a `let` because of clear and import.
  let reg: r.Registry = {
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
  const e4 = 'e4';
  const e4a = { id: 'e4a' };
  const e4b = 'e4b';
  const e1b = 'e1b';

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

  test('add string entities', () => {
    r.add(reg, e4);
    expect(r.size(reg)).toBe(9);
    expect(r.printAll(reg)).toBe(`  e1 | *
  e2 | *
  e3 | *
 e1a | e1
 e2a | e2
 e2b | e2
 e3a | e3
 e3b | e3
  e4 | *
`);

    // EntityType under string.
    r.add(reg, e4a, e4);
    expect(r.size(reg)).toBe(10);
    expect(r.printAll(reg)).toBe(`  e1 | *
  e2 | *
  e3 | *
 e1a | e1
 e2a | e2
 e2b | e2
 e3a | e3
 e3b | e3
  e4 | *
 e4a | e4
`);

    // String under string.
    r.add(reg, e4b, e4);
    expect(r.size(reg)).toBe(11);
    expect(r.printAll(reg)).toBe(`  e1 | *
  e2 | *
  e3 | *
 e1a | e1
 e2a | e2
 e2b | e2
 e3a | e3
 e3b | e3
  e4 | *
 e4a | e4
 e4b | e4
`);

    // String under entity.
    r.add(reg, e1b, e1);
    expect(r.size(reg)).toBe(12);
    expect(r.printAll(reg)).toBe(`  e1 | *
  e2 | *
  e3 | *
 e1a | e1
 e2a | e2
 e2b | e2
 e3a | e3
 e3b | e3
  e4 | *
 e4a | e4
 e4b | e4
 e1b | e1
`);
  });

  test('Clone/Clear/Import/Traverse', () => {
    const clone = r.clone(reg);
    expect(clone).toEqual({
      records: {
        e1: {
          id: 'e1',
        },
        e2: {
          id: 'e2',
        },
        e3: {
          id: 'e3',
        },
        e4: 'e4',
        e1a: {
          id: 'e1a',
        },
        e2a: {
          id: 'e2a',
        },
        e2b: {
          id: 'e2b',
        },
        e3a: {
          id: 'e3a',
        },
        e3b: {
          id: 'e3b',
        },
        e4a: {
          id: 'e4a',
        },
        e4b: 'e4b',
        e1b: 'e1b',
      },
      register: {
        e1: ROOT_ENTITY,
        e2: ROOT_ENTITY,
        e3: ROOT_ENTITY,
        e1a: e1.id,
        e2a: e2.id,
        e2b: e2.id,
        e3a: e3.id,
        e3b: e3.id,
        e4: ROOT_ENTITY,
        e4a: e4,
        e4b: e4,
        e1b: e1.id,
      },
    });

    expect(r.getChildIds(reg, e2)).toEqual([e2a.id, e2b.id]);
    expect(r.getChildIds(reg, ROOT_ENTITY)).toEqual([e1.id, e2.id, e3.id, e4]);
    expect(r.getRecord(reg, 'e2')).toEqual({ id: 'e2' });
    expect(r.has(reg, e2)).toBe(true);
    expect(r.has(reg, e1a1)).toBe(false);
    expect(r.hasChild(reg, e1)).toBe(true);
    expect(r.hasChild(reg, e1a)).toBe(false);

    r.clear(reg);
    expect(reg.records).toEqual({});
    expect(reg.register).toEqual({});

    const regi = r.recreate(clone);
    reg = regi; // Re-assign for "Remove" tests.

    expect(r.size(regi)).toBe(12);
    expect(r.printAll(reg)).toBe(`  e1 | *
  e2 | *
  e3 | *
 e1a | e1
 e2a | e2
 e2b | e2
 e3a | e3
 e3b | e3
  e4 | *
 e4a | e4
 e4b | e4
 e1b | e1
`);
  });

  test('recreate coverage', () => {
    const in1 = {
      records: '',
      register: {},
    };
    expect(() => {
      r.recreate(in1);
    }).toThrow(InvalidTypeError);

    const in2 = {
      records: {},
      register: 0,
    };
    expect(() => {
      r.recreate(in2);
    }).toThrow(InvalidTypeError);
  });

  test('Remove entries', () => {
    expect(r.size(reg)).toBe(12);
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
  e4 | *
 e4a | e4
 e4b | e4
 e1b | *
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
  e4 | *
 e4a | e4
 e4b | e4
 e1b | *
`);

    removed = r.remove(reg, e3, true);
    expect(removed.length).toBe(3);
    expect(removed).toEqual([{ id: 'e3a' }, { id: 'e3b' }, { id: 'e3' }]);
    expect(r.printAll(reg)).toBe(` e1a | *
 e2a | *
 e2b | *
  e4 | *
 e4a | e4
 e4b | e4
 e1b | *
`);

    removed = r.remove(reg, e2a);
    expect(removed.length).toBe(1);
    expect(removed).toEqual([{ id: 'e2a' }]);
    expect(r.printAll(reg)).toBe(` e1a | *
 e2b | *
  e4 | *
 e4a | e4
 e4b | e4
 e1b | *
`);
  });
});

describe('4 levels', () => {
  const reg: r.Registry = {
    records: {},
    register: {},
  };

  const e1 = { id: 'e1' };
  const e2 = { id: 'e2' };
  const e3 = { id: 'e3' };
  const e1a = { id: 'e1a' };
  const e1b = { id: 'e1b' };
  const e2a = { id: 'e2a' };
  const e2b = { id: 'e2b' };
  const e1a1 = { id: 'e1a1' };
  const e1b1 = { id: 'e1b1' };
  const e2a1 = { id: 'e2a1' };
  const e2a2 = { id: 'e2a2' };
  const e2b1 = { id: 'e2b1' };
  const e2b2 = { id: 'e2b2' };
  const e3a = { id: 'e3a' };
  const e3b = { id: 'e3b' };
  const e3a1 = { id: 'e3a1' };
  const e3a2 = { id: 'e3a2' };
  const e3a3 = { id: 'e3a3' };
  const e3b1 = { id: 'e3b1' };
  const e3b2 = { id: 'e3b2' };
  const e3b3 = { id: 'e3b3' };
  const e3a1a = { id: 'e3a1a' };

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
    r.add(reg, e1b, e1);
    r.add(reg, e2a, e2);
    r.add(reg, e2b, e2);
    r.add(reg, e3a, e3);
    r.add(reg, e3b, e3);
    expect(r.size(reg)).toBe(9);
    expect(r.printAll(reg)).toBe(`  e1 | *
  e2 | *
  e3 | *
 e1a | e1
 e1b | e1
 e2a | e2
 e2b | e2
 e3a | e3
 e3b | e3
`);

    // 3rd level
    r.add(reg, e1a1, e1a);
    r.add(reg, e1b1, e1b);
    r.add(reg, e2a1, e2a);
    r.add(reg, e2a2, e2a);
    r.add(reg, e2b1, e2b);
    r.add(reg, e2b2, e2b);
    r.add(reg, e3a1, e3a);
    r.add(reg, e3a2, e3a);
    r.add(reg, e3a3, e3a);
    r.add(reg, e3b1, e3b);
    r.add(reg, e3b2, e3b);
    r.add(reg, e3b3, e3b);
    expect(r.size(reg)).toBe(21);
    expect(r.printAll(reg)).toBe(`   e1 | *
   e2 | *
   e3 | *
  e1a | e1
  e1b | e1
  e2a | e2
  e2b | e2
  e3a | e3
  e3b | e3
 e1a1 | e1a
 e1b1 | e1b
 e2a1 | e2a
 e2a2 | e2a
 e2b1 | e2b
 e2b2 | e2b
 e3a1 | e3a
 e3a2 | e3a
 e3a3 | e3a
 e3b1 | e3b
 e3b2 | e3b
 e3b3 | e3b
`);

    // 4th level
    r.add(reg, e3a1a, e3a1);
    expect(r.size(reg)).toBe(22);
    expect(r.printAll(reg)).toBe(`    e1 | *
    e2 | *
    e3 | *
   e1a | e1
   e1b | e1
   e2a | e2
   e2b | e2
   e3a | e3
   e3b | e3
  e1a1 | e1a
  e1b1 | e1b
  e2a1 | e2a
  e2a2 | e2a
  e2b1 | e2b
  e2b2 | e2b
  e3a1 | e3a
  e3a2 | e3a
  e3a3 | e3a
  e3b1 | e3b
  e3b2 | e3b
  e3b3 | e3b
 e3a1a | e3a1
`);
    // Show the deepest path.
    expect(r.traverseToRoot(reg, e3a1a)).toEqual([
      'e3a1a',
      'e3a1',
      'e3a',
      'e3',
      '*',
    ]);
    expect(r.traverseToRoot(reg, e3a)).toEqual(['e3a', 'e3', '*']);

    // Show the most complex tree.
    expect(r.print(reg, ROOT_ENTITY)).toBe(`- *
  - e1
    - e1a
      - e1a1
    - e1b
      - e1b1
  - e2
    - e2a
      - e2a1
      - e2a2
    - e2b
      - e2b1
      - e2b2
  - e3
    - e3a
      - e3a1
        - e3a1a
      - e3a2
      - e3a3
    - e3b
      - e3b1
      - e3b2
      - e3b3
`);
    expect(r.print(reg, e3)).toBe(`- e3
  - e3a
    - e3a1
      - e3a1a
    - e3a2
    - e3a3
  - e3b
    - e3b1
    - e3b2
    - e3b3
`);
  });

  test('Remove entries', () => {
    let removed = r.remove(reg, e1a, true);
    expect(removed.length).toBe(2);
    expect(removed).toEqual([{ id: 'e1a1' }, { id: 'e1a' }]);
    expect(r.size(reg)).toBe(20);
    expect(r.printAll(reg)).toBe(`    e1 | *
    e2 | *
    e3 | *
   e1b | e1
   e2a | e2
   e2b | e2
   e3a | e3
   e3b | e3
  e1b1 | e1b
  e2a1 | e2a
  e2a2 | e2a
  e2b1 | e2b
  e2b2 | e2b
  e3a1 | e3a
  e3a2 | e3a
  e3a3 | e3a
  e3b1 | e3b
  e3b2 | e3b
  e3b3 | e3b
 e3a1a | e3a1
`);

    removed = r.remove(reg, e1b, false);
    expect(removed.length).toBe(1);
    expect(removed).toEqual([{ id: 'e1b' }]);
    expect(r.size(reg)).toBe(19);
    expect(r.printAll(reg)).toBe(`    e1 | *
    e2 | *
    e3 | *
   e2a | e2
   e2b | e2
   e3a | e3
   e3b | e3
  e1b1 | e1
  e2a1 | e2a
  e2a2 | e2a
  e2b1 | e2b
  e2b2 | e2b
  e3a1 | e3a
  e3a2 | e3a
  e3a3 | e3a
  e3b1 | e3b
  e3b2 | e3b
  e3b3 | e3b
 e3a1a | e3a1
`);

    // Remove an entire branch.
    removed = r.remove(reg, e2, true);
    expect(removed.length).toBe(7);
    expect(removed).toEqual([
      { id: 'e2a1' },
      { id: 'e2a2' },
      { id: 'e2a' },
      { id: 'e2b1' },
      { id: 'e2b2' },
      { id: 'e2b' },
      { id: 'e2' },
    ]);
    expect(r.size(reg)).toBe(12);
    expect(r.printAll(reg)).toBe(`    e1 | *
    e3 | *
   e3a | e3
   e3b | e3
  e1b1 | e1
  e3a1 | e3a
  e3a2 | e3a
  e3a3 | e3a
  e3b1 | e3b
  e3b2 | e3b
  e3b3 | e3b
 e3a1a | e3a1
`);

    // Remove intermediate levels.
    removed = r.remove(reg, e3, false);
    expect(removed.length).toBe(1);
    expect(removed).toEqual([{ id: 'e3' }]);
    expect(r.size(reg)).toBe(11);
    expect(r.printAll(reg)).toBe(`    e1 | *
   e3a | *
   e3b | *
  e1b1 | e1
  e3a1 | e3a
  e3a2 | e3a
  e3a3 | e3a
  e3b1 | e3b
  e3b2 | e3b
  e3b3 | e3b
 e3a1a | e3a1
`);
    expect(r.traverseToRoot(reg, e3a1a)).toEqual(['e3a1a', 'e3a1', 'e3a', '*']);

    removed = r.remove(reg, e3a1, false);
    expect(removed.length).toBe(1);
    expect(removed).toEqual([{ id: 'e3a1' }]);
    expect(r.size(reg)).toBe(10);
    expect(r.printAll(reg)).toBe(`    e1 | *
   e3a | *
   e3b | *
  e1b1 | e1
  e3a2 | e3a
  e3a3 | e3a
  e3b1 | e3b
  e3b2 | e3b
  e3b3 | e3b
 e3a1a | e3a
`);
    expect(r.traverseToRoot(reg, e3a1a)).toEqual(['e3a1a', 'e3a', '*']);
  });
});

describe('Save/Load', () => {
  test(`entities as strings`, () => {
    const e1 = 'e1';
    const e2 = 'e2';

    const reg: r.Registry = {
      records: {},
      register: {},
    };

    r.add(reg, e1);
    r.add(reg, e2, e1);
    const json = r.saveToJson(reg);
    expect(json).toBe(
      `{"records":{"e1":"e1","e2":"e2"},"register":{"e1":"*","e2":"e1"}}`
    );

    const result = r.loadFromJson(json);
    expect(r.printAll(result)).toBe(` e1 | *
 e2 | e1
`);
    expect(r.getRecord(result, e1)).toBe(e1);
    expect(r.getRecord(result, e2)).toBe(e2);
  });

  test(`entities with string IDs as types`, () => {
    type User = {
      id: string;
      name: string;
    };
    const u1: User = {
      id: 'u1',
      name: 'User One',
    };
    const u2: User = {
      id: 'u2',
      name: 'User Two',
    };

    const reg: r.Registry = {
      records: {},
      register: {},
    };

    r.add(reg, u1);
    r.add(reg, u2, u1);
    const json = r.saveToJson(reg);
    expect(json).toBe(
      `{"records":{"u1":{"id":"u1","name":"User One"},"u2":{"id":"u2","name":"User Two"}},"register":{"u1":"*","u2":"u1"}}`
    );

    const result = r.loadFromJson(json);
    expect(r.printAll(result)).toBe(` u1 | *
 u2 | u1
`);
    expect(r.getRecord(result, u1.id)).toEqual(u1);
    expect(r.getRecord(result, u2.id)).toEqual(u2);
  });

  test(`entities with numeric IDs as types`, () => {
    type User = {
      id: number;
      name: string;
    };
    const u1: User = {
      id: 1,
      name: 'TypeUser One',
    };
    const u2: User = {
      id: 2,
      name: 'TypeUser Two',
    };

    const reg: r.Registry = {
      records: {},
      register: {},
    };

    r.add(reg, u1);
    r.add(reg, u2, u1);
    const json = r.saveToJson(reg);
    expect(json).toBe(
      `{"records":{"1":{"id":1,"name":"TypeUser One"},"2":{"id":2,"name":"TypeUser Two"}},"register":{"1":"*","2":"1"}}`
    );

    const result = r.loadFromJson(json);
    expect(r.printAll(result)).toBe(` 1 | *
 2 | 1
`);
    expect(r.getRecord(result, u1.id.toString())).toEqual(u1);
    expect(r.getRecord(result, u2.id.toString())).toEqual(u2);
  });

  test(`entities with string IDs as classes`, () => {
    class User {
      id: string;
      name: string;

      constructor(id: string, name: string) {
        this.id = id;
        this.name = name;
      }

      public print(): string {
        return `${this.id} - ${this.name}`;
      }
    }
    const u1 = new User('u1', 'ClassUser One');
    const u2 = new User('u2', 'ClassUser Two');

    const reg: r.Registry = {
      records: {},
      register: {},
    };

    r.add(reg, u1);
    r.add(reg, u2, u1);
    const json = r.saveToJson(reg);
    expect(json).toBe(
      `{"records":{"u1":{"id":"u1","name":"ClassUser One"},"u2":{"id":"u2","name":"ClassUser Two"}},"register":{"u1":"*","u2":"u1"}}`
    );

    const result = r.loadFromJson(json);
    expect(r.printAll(result)).toBe(` u1 | *
 u2 | u1
`);
    const r1 = r.getRecord(result, u1.id);
    expect(r1).toEqual(u1);
    const r2 = r.getRecord(result, u2.id);
    expect(r2).toEqual(u2);
  });

  test(`entities with numeric IDs as classes`, () => {
    class User {
      id: number;
      name: string;

      constructor(id: number, name: string) {
        this.id = id;
        this.name = name;
      }

      public get getId() {
        return this.id.toString();
      }

      public print(): string {
        return `${this.id} - ${this.name}`;
      }
    }
    const u1 = new User(1, 'ClassUser One');
    const u2 = new User(2, 'ClassUser Two');

    const reg: r.Registry = {
      records: {},
      register: {},
    };

    r.add(reg, u1);
    r.add(reg, u2, u1);
    const json = r.saveToJson(reg);
    expect(json).toBe(
      `{"records":{"1":{"id":1,"name":"ClassUser One"},"2":{"id":2,"name":"ClassUser Two"}},"register":{"1":"*","2":"1"}}`
    );

    const result = r.loadFromJson(json);
    expect(r.printAll(result)).toBe(` 1 | *
 2 | 1
`);
    const r1 = r.getRecord(result, u1.getId);
    const r2 = r.getRecord(result, u2.getId);
    expect(r1).toEqual(u1);
    expect(r2).toEqual(u2);
  });
});
