-- The audit log keeps its entries for the configured retention (audit.retention, audit.max_entries). Pruning is the
-- only delete there is, and the database refuses to delete one of the newest 1000 entries.
DROP TRIGGER audit_no_delete;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit
WHEN OLD.id > (SELECT MAX(id) FROM audit) - 1000
BEGIN SELECT RAISE(ABORT, 'audit log: the newest 1000 entries are never deleted'); END;
