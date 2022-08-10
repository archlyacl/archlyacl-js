import { expect, test } from 'vitest';
import { DuplicateError } from './errors';
import * as r from './registry';

test('Add/Remove entries', () => {
  const reg: r.Registry = {
    records: {},
    register: {},
  };
  const e1 = { id: 'e1' };
  const e2 = { id: 'e2' };
  const e1a = { id: 'e1a' };
  const e2a = { id: 'e2a' };
  const e2b = { id: 'e2b' };
  const e1a1 = { id: 'e1a1' };
  const e2a1 = { id: 'e2a1' };
  const e2a2 = { id: 'e2a2' };
  const e2b1 = { id: 'e2b1' };
  const e2b2 = { id: 'e2b2' };

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
  expect(r.size(reg)).toBe(2);
  expect(r.printAll(reg)).toBe(` e1 | *
 e2 | *
`);

  // 1st level children.
  r.add(reg, e1a, e1);
  r.add(reg, e2a, e2);
  r.add(reg, e2b, e2);
  expect(r.size(reg)).toBe(5);
  expect(r.printAll(reg)).toBe(`  e1 | *
  e2 | *
 e1a | e1
 e2a | e2
 e2b | e2
`);

  // 2nd level children.
  r.add(reg, e2b2, e2b);
  r.add(reg, e2b1, e2b);
  r.add(reg, e2a2, e2a);
  r.add(reg, e2a1, e2a);
  r.add(reg, e1a1, e1a);
  expect(r.size(reg)).toBe(10);
  expect(r.printAll(reg)).toBe(`   e1 | *
   e2 | *
  e1a | e1
  e2a | e2
  e2b | e2
 e2b2 | e2b
 e2b1 | e2b
 e2a2 | e2a
 e2a1 | e2a
 e1a1 | e1a
`);
});
