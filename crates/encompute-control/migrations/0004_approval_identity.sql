-- Encompute control plane, schema version 4: sharing grants, project
-- memberships and organization roles with an identity.
--
-- Every asset approval, every organization it covers, every project
-- membership (or invitation) and every role a principal holds in an
-- organization gets an ID that is never reused: an approval given again
-- after a withdrawal is a new one, so is an organization that joins a
-- project again after leaving it, and so is a role granted again after it
-- was removed. A withdrawn approval, an organization's grant ended by
-- leaving the project, the membership it left and a removed role are
-- recorded here and anchored outside the database, so a restored backup
-- that still holds one is refused at startup instead of silently sharing
-- the asset, or the project, again, or giving the role back.
--
-- Existing rows get IDs derived from their content (asset, project,
-- purpose, organization, principal, role, creation time): a backup taken
-- before this migration and migrated after a restore gets the same IDs
-- again.

ALTER TABLE asset_approvals ADD COLUMN approval_id TEXT;
UPDATE asset_approvals
   SET approval_id = 'apv_' || md5(json_build_array(
           asset_id, project_id, purpose, extract(epoch FROM created_at)::text)::text);
ALTER TABLE asset_approvals ALTER COLUMN approval_id SET NOT NULL;
ALTER TABLE asset_approvals ADD CONSTRAINT asset_approvals_approval_id UNIQUE (approval_id);

ALTER TABLE asset_approval_members ADD COLUMN grant_id TEXT;
UPDATE asset_approval_members
   SET grant_id = 'apg_' || md5(json_build_array(
           asset_id, project_id, purpose, organization_id, extract(epoch FROM created_at)::text)::text);
ALTER TABLE asset_approval_members ALTER COLUMN grant_id SET NOT NULL;
ALTER TABLE asset_approval_members ADD CONSTRAINT asset_approval_members_grant_id UNIQUE (grant_id);

-- Withdrawn approvals and ended grants (never deleted): what the state
-- anchor must keep withdrawn.
CREATE TABLE withdrawn_grants (
    id              TEXT PRIMARY KEY,
    kind            TEXT NOT NULL CHECK (kind IN ('approval', 'grant')),
    asset_id        TEXT NOT NULL,
    project_id      TEXT NOT NULL,
    purpose         TEXT NOT NULL,
    -- The organization a grant covered (NULL for a whole approval).
    organization_id TEXT,
    withdrawn_by    TEXT NOT NULL,
    withdrawn_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE project_members ADD COLUMN membership_id TEXT;
UPDATE project_members
   SET membership_id = 'pmb_' || md5(json_build_array(
           project_id, organization_id, extract(epoch FROM created_at)::text)::text);
ALTER TABLE project_members ALTER COLUMN membership_id SET NOT NULL;
ALTER TABLE project_members ADD CONSTRAINT project_members_membership_id UNIQUE (membership_id);

-- Memberships (and invitations) removed from a project (never deleted):
-- what the state anchor must keep removed.
CREATE TABLE removed_memberships (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    removed_by      TEXT NOT NULL,
    removed_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- (Filled by rewriting the column rather than by an UPDATE: no migration
-- writes to the roles themselves.)
ALTER TABLE memberships ADD COLUMN membership_id TEXT;
ALTER TABLE memberships ALTER COLUMN membership_id TYPE TEXT
    USING 'rol_' || md5(json_build_array(
              principal_id, organization_id, role, extract(epoch FROM created_at)::text)::text);
ALTER TABLE memberships ALTER COLUMN membership_id SET NOT NULL;
-- The control plane names new roles itself; a row written some other way
-- still gets a fresh ID (never one a removed role had).
ALTER TABLE memberships ALTER COLUMN membership_id
    SET DEFAULT 'rol_' || replace(gen_random_uuid()::text, '-', '');
ALTER TABLE memberships ADD CONSTRAINT memberships_membership_id UNIQUE (membership_id);

-- Roles removed from principals (never deleted): what the state anchor
-- must keep removed.
CREATE TABLE removed_roles (
    id              TEXT PRIMARY KEY,
    principal_id    TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    role            TEXT NOT NULL,
    removed_by      TEXT NOT NULL,
    removed_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
