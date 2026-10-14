create table "scimConnectionBinding" (
  "id" TEXT PRIMARY KEY,
  "connectionId" TEXT NOT NULL,
  "connectionKey" TEXT NOT NULL UNIQUE,
  "provisioningDomainId" TEXT NOT NULL,
  "createdAt" TEXT NOT NULL,
  "decommissionStatus" TEXT NOT NULL DEFAULT 'active',
  "decommissionCursorUserId" TEXT,
  "decommissionReconciledUserCount" INTEGER NOT NULL DEFAULT 0,
  "decommissionBatchCount" INTEGER NOT NULL DEFAULT 0,
  "decommissionRevision" INTEGER NOT NULL DEFAULT 0,
  "decommissionedAt" TEXT,
  "decommissionCompletedAt" TEXT,
  "decommissionLeaseId" TEXT,
  "decommissionLeaseExpiresAt" TEXT
);
create index "scimConnectionBinding_connectionId_idx" on "scimConnectionBinding" ("connectionId");
