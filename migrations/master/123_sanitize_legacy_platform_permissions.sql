-- Remove the old platform permission catalogue seeded into workspace admin roles.
--
-- Console access is now authorized by workspace role bindings (owner/admin),
-- not synthetic permission rows like admin:access, users:read, clients:create,
-- or user-rbac-roles:manage.
--
-- Application/resource-server access remains scope-driven. Preserve permission
-- rows that are referenced by oauth_scope_permissions because OAuth scopes use
-- those mappings for protected application access.

DELETE FROM role_permissions rp
USING roles r
WHERE rp.role_id = r.id
  AND r.name IN ('owner', 'admin', 'member');

DELETE FROM role_permissions rp
USING permissions p
WHERE rp.permission_id = p.id
  AND NOT EXISTS (
    SELECT 1
    FROM oauth_scope_permissions osp
    WHERE osp.permission_id = p.id
  );

DELETE FROM permissions p
WHERE NOT EXISTS (
  SELECT 1
  FROM oauth_scope_permissions osp
  WHERE osp.permission_id = p.id
);
