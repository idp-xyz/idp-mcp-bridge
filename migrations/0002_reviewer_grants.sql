-- idp-mcp-bridge schema v2 (ADR-0001 D33): the reviewer account of a connection.
--
-- A connection's reviewer grant belongs to the connection, not to a member: one row per connection with reviewer = true, tenant and
-- member empty (the operator who authorized it is in authorized_by, for the record). It is a row of the same table so that it is
-- sealed, renewed under the same row lock and revoked the same way, and it is told apart from every member's grant by the key
-- (reviewer is part of the primary key and of the additional data of the seal).

ALTER TABLE grants ADD COLUMN reviewer boolean NOT NULL DEFAULT false;
ALTER TABLE grants ADD COLUMN authorized_by text NOT NULL DEFAULT '';   -- tenant/member of the operator who made a reviewer grant
ALTER TABLE grants DROP CONSTRAINT grants_pkey;
ALTER TABLE grants DROP CONSTRAINT grants_tenant_check;
ALTER TABLE grants DROP CONSTRAINT grants_member_check;
ALTER TABLE grants ADD PRIMARY KEY (tenant, member, connection, reviewer);
ALTER TABLE grants ADD CONSTRAINT grants_owner_check CHECK (
  (reviewer AND tenant = '' AND member = '') OR (NOT reviewer AND tenant <> '' AND member <> ''));

ALTER TABLE pending_states ADD COLUMN reviewer boolean NOT NULL DEFAULT false;   -- an authorization of the reviewer account
