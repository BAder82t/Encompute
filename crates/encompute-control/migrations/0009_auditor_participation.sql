-- Encompute control plane, schema version 9: auditor organizations in
-- governed projects (governed projects, part 4).
--
-- An organization takes part in a project as a member (as before) or, in
-- a governed project only, as an auditor: it reads the project's shared
-- governance records (authorizations with pseudonymous approvers,
-- purposes, jobs, the project's audit events) and changes nothing. It
-- never owns a source there, submits, receives a release, approves or
-- holds a key. How an organization takes part is fixed when it is
-- invited: a different participation is a new membership.
--
-- Existing memberships stay members. Standard projects have no auditor
-- organizations.

ALTER TABLE project_members ADD COLUMN participation TEXT NOT NULL DEFAULT 'member'
    CHECK (participation IN ('member', 'auditor'));

CREATE FUNCTION encompute_project_participation_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.participation IS DISTINCT FROM OLD.participation THEN
        RAISE EXCEPTION 'how an organization takes part in a project is immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.participation = 'auditor' THEN
        IF NOT EXISTS (SELECT 1 FROM projects p WHERE p.id = NEW.project_id
                          AND p.governance = 'governed' AND p.organization_id <> NEW.organization_id) THEN
            RAISE EXCEPTION 'auditor organizations take part only in governed projects, never their own'
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER project_members_participation BEFORE INSERT OR UPDATE ON project_members
    FOR EACH ROW EXECUTE FUNCTION encompute_project_participation_guard();

-- A governed project's shared audit view reads its events by project.
CREATE INDEX audit_events_project ON audit_events (project_id, seq) WHERE project_id IS NOT NULL;
