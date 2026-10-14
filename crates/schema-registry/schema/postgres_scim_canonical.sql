create table "scimIdentityTombstone" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "connectionId" TEXT NOT NULL,
  "provisioningDomainId" TEXT NOT NULL,
  "externalId" TEXT NOT NULL,
  "externalIdKey" TEXT NOT NULL UNIQUE,
  "userId" TEXT NOT NULL REFERENCES "user" ("id") ON DELETE CASCADE,
  "profile" TEXT NOT NULL,
  "deletedAt" TIMESTAMPTZ NOT NULL
);

create index "scimIdentityTombstone_connectionId_idx" on "scimIdentityTombstone" ("connectionId");

create index "scimIdentityTombstone_provisioningDomainId_idx" on "scimIdentityTombstone" ("provisioningDomainId");

create index "scimIdentityTombstone_userId_idx" on "scimIdentityTombstone" ("userId");

create table "scimSubject" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "userId" TEXT NOT NULL UNIQUE REFERENCES "user" ("id") ON DELETE CASCADE,
  "profileSourceId" TEXT,
  "revision" INTEGER NOT NULL,
  "createdAt" TIMESTAMPTZ NOT NULL,
  "updatedAt" TIMESTAMPTZ NOT NULL
);

create index "scimSubject_profileSourceId_idx" on "scimSubject" ("profileSourceId");

create table "scimUser" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "connectionId" TEXT NOT NULL,
  "provisioningDomainId" TEXT NOT NULL,
  "userId" TEXT NOT NULL REFERENCES "user" ("id") ON DELETE CASCADE,
  "connectionUserKey" TEXT NOT NULL UNIQUE,
  "userName" TEXT NOT NULL,
  "userNameKey" TEXT NOT NULL UNIQUE,
  "primaryEmail" TEXT NOT NULL,
  "workEmailValueIndex" TEXT NOT NULL,
  "emailValueIndex" TEXT NOT NULL,
  "displayName" TEXT NOT NULL,
  "formattedName" TEXT NOT NULL,
  "givenName" TEXT,
  "familyName" TEXT,
  "serializedEmails" TEXT NOT NULL,
  "serializedAttributes" TEXT,
  "externalId" TEXT,
  "externalIdKey" TEXT UNIQUE,
  "active" BOOLEAN NOT NULL,
  "orderKey" TEXT NOT NULL UNIQUE,
  "createdAt" TIMESTAMPTZ NOT NULL,
  "updatedAt" TIMESTAMPTZ NOT NULL
);

create index "scimUser_connectionId_idx" on "scimUser" ("connectionId");

create index "scimUser_provisioningDomainId_idx" on "scimUser" ("provisioningDomainId");

create index "scimUser_userId_idx" on "scimUser" ("userId");

create table "scimProjectionGrant" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "connectionId" TEXT NOT NULL,
  "provisioningDomainId" TEXT NOT NULL,
  "scimUserId" TEXT NOT NULL REFERENCES "scimUser" ("id") ON DELETE CASCADE,
  "userId" TEXT NOT NULL REFERENCES "user" ("id") ON DELETE CASCADE,
  "sourceKind" TEXT NOT NULL,
  "sourceId" TEXT NOT NULL,
  "sourceValue" TEXT,
  "role" TEXT NOT NULL,
  "grantKey" TEXT NOT NULL UNIQUE,
  "createdAt" TIMESTAMPTZ NOT NULL,
  "updatedAt" TIMESTAMPTZ NOT NULL
);

create index "scimProjectionGrant_connectionId_idx" on "scimProjectionGrant" ("connectionId");

create index "scimProjectionGrant_provisioningDomainId_idx" on "scimProjectionGrant" ("provisioningDomainId");

create index "scimProjectionGrant_scimUserId_idx" on "scimProjectionGrant" ("scimUserId");

create index "scimProjectionGrant_userId_idx" on "scimProjectionGrant" ("userId");

create table "scimGroup" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "connectionId" TEXT NOT NULL,
  "provisioningDomainId" TEXT NOT NULL,
  "revision" INTEGER NOT NULL,
  "displayName" TEXT NOT NULL,
  "displayNameKey" TEXT NOT NULL UNIQUE,
  "externalId" TEXT,
  "externalIdKey" TEXT UNIQUE,
  "orderKey" TEXT NOT NULL UNIQUE,
  "createdAt" TIMESTAMPTZ NOT NULL,
  "updatedAt" TIMESTAMPTZ NOT NULL
);

create index "scimGroup_connectionId_idx" on "scimGroup" ("connectionId");

create index "scimGroup_provisioningDomainId_idx" on "scimGroup" ("provisioningDomainId");

create table "scimGroupMember" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "connectionId" TEXT NOT NULL,
  "groupId" TEXT NOT NULL REFERENCES "scimGroup" ("id") ON DELETE CASCADE,
  "scimUserId" TEXT NOT NULL REFERENCES "scimUser" ("id") ON DELETE CASCADE,
  "membershipKey" TEXT NOT NULL UNIQUE,
  "createdAt" TIMESTAMPTZ NOT NULL
);

create index "scimGroupMember_connectionId_idx" on "scimGroupMember" ("connectionId");

create index "scimGroupMember_groupId_idx" on "scimGroupMember" ("groupId");

create index "scimGroupMember_scimUserId_idx" on "scimGroupMember" ("scimUserId");
