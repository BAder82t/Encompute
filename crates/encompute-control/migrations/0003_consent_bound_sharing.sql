-- Encompute control plane, schema version 3: sharing bound to consent.
--
-- An asset approval covers the organizations that were project members when
-- its owner approved it: an organization added later sees and uses nothing
-- of the asset until the owner approves again. And a project membership is
-- effective only once the invited organization's admin accepted it.

CREATE TABLE asset_approval_members (
    asset_id        TEXT NOT NULL,
    project_id      TEXT NOT NULL,
    purpose         TEXT NOT NULL,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (asset_id, project_id, purpose, organization_id),
    FOREIGN KEY (asset_id, project_id, purpose)
        REFERENCES asset_approvals (asset_id, project_id, purpose) ON DELETE CASCADE
);
CREATE INDEX asset_approval_members_org ON asset_approval_members (organization_id);

-- Existing approvals cover the members that had joined when they were
-- given (not later joiners: those need a new approval). Each such grant
-- dates from its approval, not from the migration: a backup restored and
-- migrated again gets the same rows, and so the same grant IDs (version 4).
INSERT INTO asset_approval_members (asset_id, project_id, purpose, organization_id, created_at)
SELECT ap.asset_id, ap.project_id, ap.purpose, pm.organization_id, ap.created_at
  FROM asset_approvals ap
  JOIN project_members pm ON pm.project_id = ap.project_id
 WHERE pm.created_at <= ap.created_at;

-- Existing memberships stay effective; new ones start as invitations.
ALTER TABLE project_members
    ADD COLUMN status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('invited', 'active'));
