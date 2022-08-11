export const ROOT_ENTITY = '*';

export type Entity = EntityType | string;

export interface EntityType {
  id: string | number;
}
