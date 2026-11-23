-- idp-mcp-bridge schema v3 (ADR-0001 D38 to D41): a member who left, and a revocation that could not be confirmed.

-- the authorizer of a connection's reviewer account left: the grant is kept (removing it would make the service unusable for every
-- member) and marked, so that the operators' list says so and an alert is raised
ALTER TABLE grants ADD COLUMN authorizer_left boolean NOT NULL DEFAULT false;

-- a member disconnected, and the third party's revocation did not succeed or could not be confirmed: the member is told to revoke by
-- hand where the third party lets them; the row goes when the member connects again
CREATE TABLE unconfirmed_revocations (
  tenant     text        NOT NULL CHECK (tenant <> ''),
  member     text        NOT NULL CHECK (member <> ''),
  connection text        NOT NULL,
  at         timestamptz NOT NULL,
  PRIMARY KEY (tenant, member, connection)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON unconfirmed_revocations TO idp_bridge_app;
