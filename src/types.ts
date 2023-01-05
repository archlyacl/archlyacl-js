/**
 * @module types
 */

/**
 * The action types available.
 */
const ACTION_TYPES = ['create', 'delete', 'read', 'update'];

type ActionTuple = typeof ACTION_TYPES;
type ActionType = ActionTuple[number];

/**
 * The Access object describing the access to specific actions.
 */
export type Access = {
  [K in ActionType]?: boolean;
};

/**
 * The action types, including `all`.
 */
export type ActionAllType = keyof Access | 'all';

/**
 * The representation of the root of a registry.
 */
export const ROOT_ENTITY = '*';

/**
 * The type accepted by registries.
 */
export type Entity = EntityType | string;

/**
 * The subtype accepted by registries.
 */
export interface EntityType {
  id: string | number;
}
