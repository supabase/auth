package store

const selectEdges = `
SELECT source_id, attribute, target_id
FROM scim_resource_references
WHERE source_id = ?
  OR target_id = ?`

const bumpResources = `
UPDATE scim_resources
SET updated_at = greatest(now(), updated_at + interval '1 microsecond')
WHERE sso_provider_id = ?
  AND id = any(?::uuid[])
  AND deleted_at IS NULL`

const selectCycle = `
WITH RECURSIVE up (id) AS (
  SELECT ?::uuid
  UNION
  SELECT r.source_id
  FROM up u
  JOIN scim_resource_references r ON r.target_id = u.id AND r.attribute = ?
)
SELECT id
FROM up
WHERE id = any(?::uuid[])
LIMIT 1`

const softDeleteResource = `
UPDATE scim_resources
SET deleted_at = now()
WHERE id = ?
  AND ` + scopeWhere + `
  AND updated_at = COALESCE(?, updated_at)`

const scopeWhere = "sso_provider_id = ? AND resource_type = ? AND deleted_at IS NULL"

const selectResources = `
SELECT id, %s AS resource, created_at, updated_at
FROM %s`

const resourceByID = `scim_resources
WHERE id = ?
  AND ` + scopeWhere

const pageOfResources = `unnest(array(%s LIMIT $%d OFFSET $%d)) WITH ORDINALITY page(id, n)
JOIN scim_resources USING (id)
ORDER BY page.n`

const selectBody = `
SELECT resource_type, resource
FROM scim_resources
WHERE id = ?`

const updateBody = `
UPDATE scim_resources
SET resource = ?::jsonb
WHERE id = ?`

const insertResource = `
INSERT INTO scim_resources (id, sso_provider_id, resource_type, resource, lower_name)
VALUES (?, ?, ?, ?::jsonb, ?)`

const stampsReturned = `
RETURNING created_at, updated_at`

const updateResource = `
UPDATE scim_resources
SET resource = ?::jsonb, lower_name = ?, updated_at = now()
WHERE id = ?
  AND ` + scopeWhere + `
  AND updated_at = COALESCE(?, updated_at)`

const insertReferences = `
INSERT INTO scim_resource_references (sso_provider_id, source_id, attribute, target_id, target_type)
SELECT sso_provider_id, ?, ?, id, resource_type
FROM scim_resources
WHERE sso_provider_id = ?
  AND resource_type = any(?::text[])
  AND deleted_at IS NULL
  AND id = any(?::uuid[])
RETURNING target_id`

const deleteReferences = `
DELETE FROM scim_resource_references
WHERE source_id = ?
  AND attribute = ?
  AND target_id = any(?::uuid[])`

const selectTargets = `
SELECT target_id
FROM scim_resource_references
WHERE source_id = ?
  AND attribute = ?`
