import { getValue } from './functions';

type Access = 'allow' | 'deny';

export function newAcl(defaultAccess: Access) {
  return defaultAccess;
}

export { getValue };
