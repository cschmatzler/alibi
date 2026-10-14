create table "scimManagedConnection" (
  "id" TEXT PRIMARY KEY,
  "creationRequestId" TEXT NOT NULL UNIQUE,
  "connectionId" TEXT NOT NULL UNIQUE,
  "provisioningDomainId" TEXT NOT NULL,
  "status" TEXT NOT NULL,
  "revision" INTEGER NOT NULL,
  "createdAt" TEXT NOT NULL,
  "createdBy" TEXT NOT NULL,
  "decommissionStartedAt" TEXT,
  "decommissionStartedBy" TEXT,
  "decommissionedAt" TEXT,
  "decommissionedBy" TEXT
);

create index "scimManagedConnection_provisioningDomainId_idx" on "scimManagedConnection" ("provisioningDomainId");

create table "scimManagedCredential" (
  "id" TEXT PRIMARY KEY,
  "connectionRecordId" TEXT NOT NULL REFERENCES "scimManagedConnection" ("id") ON DELETE CASCADE,
  "credentialId" TEXT NOT NULL UNIQUE,
  "tokenDigest" TEXT NOT NULL,
  "hashVersion" TEXT NOT NULL,
  "activeSlotKey" TEXT NOT NULL UNIQUE,
  "status" TEXT NOT NULL,
  "serializedScopes" TEXT NOT NULL,
  "expiresAt" TEXT NOT NULL,
  "createdAt" TEXT NOT NULL,
  "createdBy" TEXT NOT NULL,
  "lastUsedAt" TEXT,
  "revokedAt" TEXT,
  "revokedBy" TEXT,
  "decommissionedAt" TEXT
);

create index "scimManagedCredential_connectionRecordId_idx" on "scimManagedCredential" ("connectionRecordId");

create table "scimManagedConnectionEvent" (
  "id" TEXT PRIMARY KEY,
  "connectionRecordId" TEXT NOT NULL REFERENCES "scimManagedConnection" ("id") ON DELETE CASCADE,
  "eventKey" TEXT NOT NULL UNIQUE,
  "sequence" INTEGER NOT NULL,
  "type" TEXT NOT NULL,
  "actorId" TEXT NOT NULL,
  "credentialId" TEXT,
  "createdAt" TEXT NOT NULL
);

create index "scimManagedConnectionEvent_connectionRecordId_idx" on "scimManagedConnectionEvent" ("connectionRecordId");
