import { describe, test, expect, afterAll } from 'vitest';
import { InvalidTypeError } from './errors';
import {
  getValue,
  isTraceLevel1,
  isTraceLevel2,
  isTraceLevel3,
  isTraceLevel4,
} from './functions';

describe('getValue', () => {
  class Player {
    name: string;
    id: string | number;

    constructor(id: string | number, name: string) {
      this.id = id;
      this.name = name;
    }
  }

  // class Hero {
  //   name: string;

  //   constructor(name: string) {
  //     this.name = name;
  //   }

  //   getId(): string {
  //     return this.name.toUpperCase();
  //   }
  // }

  class Equipment {
    name: string;

    constructor(name: string) {
      this.name = name;
    }

    get id() {
      return this.name.toUpperCase();
    }
  }

  type strAlias = string;
  const s1: strAlias = 's1';
  type constantValue = 'consistent' | 'inconsistent';
  const s2: constantValue = 'consistent';

  const cases = [
    {
      title: 'of an object with the string ID property',
      in: {
        id: '23',
        name: 'Michael Jordan',
      },
      be: '23',
    },
    {
      title: 'of an object with the numeric ID property',
      in: {
        id: 23,
        name: 'M.J.',
      },
      be: '23',
    },
    // {
    //   title: 'of an object with the getId method',
    //   in: {
    //     name: 'Spider-Man',
    //     getId: function () {
    //       return 'peter-parker';
    //     },
    //   },
    //   be: 'peter-parker',
    // },
    {
      title: 'of a class instance with the string ID property',
      in: new Player('11', 'Rukawa Haede'),
      be: '11',
    },
    {
      title: 'of a class instance with the numeric ID property',
      in: new Player(11, 'Rukawa Haede'),
      be: '11',
    },
    // {
    //   title: 'of a class instance with the getId method',
    //   in: new Hero('Spider-Man'),
    //   be: 'SPIDER-MAN',
    // },
    {
      title: 'of a class instance with the ID getter method',
      in: new Equipment('basketball'),
      be: 'BASKETBALL',
    },
    {
      title: 'of a string type',
      in: 'soccer',
      be: 'soccer',
    },
    {
      title: 'of a string alias type',
      in: s1,
      be: 's1',
    },
    {
      title: 'of fixed string types',
      in: s2,
      be: s2,
    },
  ];
  for (const c of cases) {
    test(c.title, () => {
      expect(getValue(c.in)).toBe(c.be);
    });
  }

  test('of a ineligible value', () => {
    expect(() => {
      getValue({});
    }).toThrow(InvalidTypeError);
  });
});

describe('isTraceLevel', () => {
  afterAll(() => {
    process.env.ARCHLY_TRACE_LEVEL = undefined;
  });

  test('no trace level set', () => {
    expect(isTraceLevel1()).toBe(false);
    expect(isTraceLevel2()).toBe(false);
    expect(isTraceLevel3()).toBe(false);
    expect(isTraceLevel4()).toBe(false);
  });

  test('trace level 1', () => {
    process.env.ARCHLY_TRACE_LEVEL = '1';
    expect(isTraceLevel1()).toBe(true);
    expect(isTraceLevel2()).toBe(false);
    expect(isTraceLevel3()).toBe(false);
    expect(isTraceLevel4()).toBe(false);
  });

  test('trace level 2', () => {
    process.env.ARCHLY_TRACE_LEVEL = '2';
    expect(isTraceLevel1()).toBe(true);
    expect(isTraceLevel2()).toBe(true);
    expect(isTraceLevel3()).toBe(false);
    expect(isTraceLevel4()).toBe(false);
  });

  test('trace level 3', () => {
    process.env.ARCHLY_TRACE_LEVEL = '3';
    expect(isTraceLevel1()).toBe(true);
    expect(isTraceLevel2()).toBe(true);
    expect(isTraceLevel3()).toBe(true);
    expect(isTraceLevel4()).toBe(false);
  });

  test('trace level 4', () => {
    process.env.ARCHLY_TRACE_LEVEL = '4';
    expect(isTraceLevel1()).toBe(true);
    expect(isTraceLevel2()).toBe(true);
    expect(isTraceLevel3()).toBe(true);
    expect(isTraceLevel4()).toBe(true);
  });

  test('invalid trace level', () => {
    process.env.ARCHLY_TRACE_LEVEL = 'a';
    expect(isTraceLevel1()).toBe(false);
    expect(isTraceLevel2()).toBe(false);
    expect(isTraceLevel3()).toBe(false);
    expect(isTraceLevel4()).toBe(false);
  });
});
