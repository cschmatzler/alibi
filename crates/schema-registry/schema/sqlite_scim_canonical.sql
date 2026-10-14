create table "scimIdentityTombstone" ("id" text not null primary key, "connectionId" text not null, "provisioningDomainId" text not null, "externalId" text not null, "externalIdKey" text not null unique, "userId" text not null references "user" ("id") on delete cascade, "profile" text not null, "deletedAt" date not null);

create table "scimSubject" ("id" text not null primary key, "userId" text not null unique references "user" ("id") on delete cascade, "profileSourceId" text, "revision" integer not null, "createdAt" date not null, "updatedAt" date not null);

create table "scimUser" ("id" text not null primary key, "connectionId" text not null, "provisioningDomainId" text not null, "userId" text not null references "user" ("id") on delete cascade, "connectionUserKey" text not null unique, "userName" text not null, "userNameKey" text not null unique, "primaryEmail" text not null, "workEmailValueIndex" text not null, "emailValueIndex" text not null, "displayName" text not null, "formattedName" text not null, "givenName" text, "familyName" text, "serializedEmails" text not null, "serializedAttributes" text, "externalId" text, "externalIdKey" text unique, "active" integer not null, "orderKey" text not null unique, "createdAt" date not null, "updatedAt" date not null);

create table "scimProjectionGrant" ("id" text not null primary key, "connectionId" text not null, "provisioningDomainId" text not null, "scimUserId" text not null references "scimUser" ("id") on delete cascade, "userId" text not null references "user" ("id") on delete cascade, "sourceKind" text not null, "sourceId" text not null, "sourceValue" text, "role" text not null, "grantKey" text not null unique, "createdAt" date not null, "updatedAt" date not null);

create table "scimGroup" ("id" text not null primary key, "connectionId" text not null, "provisioningDomainId" text not null, "revision" integer not null, "displayName" text not null, "displayNameKey" text not null unique, "externalId" text, "externalIdKey" text unique, "orderKey" text not null unique, "createdAt" date not null, "updatedAt" date not null);

create table "scimGroupMember" ("id" text not null primary key, "connectionId" text not null, "groupId" text not null references "scimGroup" ("id") on delete cascade, "scimUserId" text not null references "scimUser" ("id") on delete cascade, "membershipKey" text not null unique, "createdAt" date not null);

create index "scimIdentityTombstone_connectionId_idx" on "scimIdentityTombstone" ("connectionId");

create index "scimIdentityTombstone_provisioningDomainId_idx" on "scimIdentityTombstone" ("provisioningDomainId");

create index "scimIdentityTombstone_userId_idx" on "scimIdentityTombstone" ("userId");

create index "scimSubject_profileSourceId_idx" on "scimSubject" ("profileSourceId");

create index "scimUser_connectionId_idx" on "scimUser" ("connectionId");

create index "scimUser_provisioningDomainId_idx" on "scimUser" ("provisioningDomainId");

create index "scimUser_userId_idx" on "scimUser" ("userId");

create index "scimProjectionGrant_connectionId_idx" on "scimProjectionGrant" ("connectionId");

create index "scimProjectionGrant_provisioningDomainId_idx" on "scimProjectionGrant" ("provisioningDomainId");

create index "scimProjectionGrant_scimUserId_idx" on "scimProjectionGrant" ("scimUserId");

create index "scimProjectionGrant_userId_idx" on "scimProjectionGrant" ("userId");

create index "scimGroup_connectionId_idx" on "scimGroup" ("connectionId");

create index "scimGroup_provisioningDomainId_idx" on "scimGroup" ("provisioningDomainId");

create index "scimGroupMember_connectionId_idx" on "scimGroupMember" ("connectionId");

create index "scimGroupMember_groupId_idx" on "scimGroupMember" ("groupId");

create index "scimGroupMember_scimUserId_idx" on "scimGroupMember" ("scimUserId");
