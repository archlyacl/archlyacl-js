# Archly ACL

Archly ACL is a project for creating a hierarchy-based access control list (ACL).

One of the objectives for this library is that it must be easy to use. To that end, there is no strict class/interface that projects using ACL must extend from. (See XXX)

## Terminology

XXX

## Architecture

Archly stores an internal representation of the hierarchies of the resources and roles. It is this internal representation that allows this library to evaluate access permissions between the roles and resources.

After the hierarchies are constructed, they can be exported (`clone`) and stored in persistent storage.

They can then be restored by importing (`recreate`) them.

If the objects are simple, they can be stored alongside the access control hierarchies in persistent storage and restored similarly.

If the objects are complex, it might be preferable that the objects are stored separately. In this case, the access control hierarchies will contain just the string IDs of the objects.

## XXX

When adding an entity (either a Resource or Role), the entity just needs to meet one of the following conditions to be used with the library:

1. be of the string type
1. has the `id` property

When the registries are exported for storage, they are represented as plain JSON objects.
