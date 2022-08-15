/**
 * @module types
 */

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
