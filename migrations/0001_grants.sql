-- idp-mcp-bridge schema v1 (ADR-0001 D24, D25).
--
-- What is here: the members' grants for third-party services, the authorizations that are under way, and the clients registered
-- dynamically. What is NOT here, in clear: a token, a code verifier or a client secret. Those columns hold what the sealer
-- made of them (AES-256-GCM, additional data = tenant, member, connection and key id): a copy of this database gives
-- ciphertext, and the key is in a Secret the database does not have. A state parameter is kept as its SHA-256.

-- The role the service runs as is a member of idp_bridge_app: NOLOGIN here, made a login by `idp-mcp-bridge ensure-login`. The
-- service never runs DDL (ADR-0001 D25): this file is run by the schema owner (`idp-mcp-bridge migrate`), and the only privileges
-- the app role gets are the four below, on the three tables, and SELECT on schema_migrations (grants.Migrate).
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'idp_bridge_app') THEN
    CREATE ROLE idp_bridge_app NOLOGIN NOBYPASSRLS;
  END IF;
END $$;

CREATE TABLE grants (
  tenant         text        NOT NULL CHECK (tenant <> ''),
  member         text        NOT NULL CHECK (member <> ''),
  connection     text        NOT NULL CHECK (connection <> ''),
  sealed_access  bytea       NOT NULL,
  sealed_refresh bytea,                        -- null: the authorization server issued no refresh token
  access_expires timestamptz,                  -- null: the server did not say
  issuer         text        NOT NULL,         -- the connection's pinned issuer when the grant was made
  scope          text        NOT NULL,         -- what was granted
  needed_scope   text        NOT NULL DEFAULT '',  -- after insufficient_scope: the union the next authorization asks for
  reauth_reason  text        NOT NULL DEFAULT '',  -- why the grant is not used until the member authorizes again
  created_at     timestamptz NOT NULL,
  refreshed_at   timestamptz NOT NULL,
  PRIMARY KEY (tenant, member, connection)
);
CREATE INDEX grants_connection ON grants (connection);   -- DeleteConnection

-- an authorization that is under way: one-time, ten minutes
CREATE TABLE pending_states (
  state_hash      bytea       PRIMARY KEY CHECK (length(state_hash) = 32),
  tenant          text        NOT NULL,
  member          text        NOT NULL,
  connection      text        NOT NULL,
  sealed_verifier bytea       NOT NULL,
  issuer          text        NOT NULL,
  redirect_uri    text        NOT NULL,
  scope           text        NOT NULL,
  client_id       text        NOT NULL,
  resource        text        NOT NULL,
  expires_at      timestamptz NOT NULL
);
CREATE INDEX pending_states_expires ON pending_states (expires_at);   -- the sweep

-- clients registered dynamically (opt-in): one per connection, issuer and redirect address
CREATE TABLE client_registrations (
  connection    text NOT NULL,
  issuer        text NOT NULL,
  redirect_uri  text NOT NULL,
  client_id     text NOT NULL,
  sealed_secret bytea,
  auth_method   text NOT NULL,
  PRIMARY KEY (connection, issuer, redirect_uri)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON grants, pending_states, client_registrations TO idp_bridge_app;   -- nothing else, on nothing else
