-- Generated from Better Auth 1.7.18 by mysql-schema-assets.mjs.

create table `scimIdentityTombstone` (`id` varchar(36) not null primary key, `connectionId` varchar(255) not null, `provisioningDomainId` varchar(255) not null, `externalId` text not null, `externalIdKey` varchar(255) not null unique, `userId` varchar(36) not null references `user` (`id`) on delete cascade, `profile` text not null, `deletedAt` timestamp(3) not null);

create table `scimSubject` (`id` varchar(36) not null primary key, `userId` varchar(36) not null unique references `user` (`id`) on delete cascade, `profileSourceId` varchar(255), `revision` integer not null, `createdAt` timestamp(3) not null, `updatedAt` timestamp(3) not null);

create table `scimUser` (`id` varchar(36) not null primary key, `connectionId` varchar(255) not null, `provisioningDomainId` varchar(255) not null, `userId` varchar(36) not null references `user` (`id`) on delete cascade, `connectionUserKey` varchar(255) not null unique, `userName` text not null, `userNameKey` varchar(255) not null unique, `primaryEmail` text not null, `workEmailValueIndex` text not null, `emailValueIndex` text not null, `displayName` text not null, `formattedName` text not null, `givenName` text, `familyName` text, `serializedEmails` text not null, `serializedAttributes` text, `externalId` text, `externalIdKey` varchar(255) unique, `active` boolean not null, `orderKey` varchar(255) not null unique, `createdAt` timestamp(3) not null, `updatedAt` timestamp(3) not null);

create table `scimProjectionGrant` (`id` varchar(36) not null primary key, `connectionId` varchar(255) not null, `provisioningDomainId` varchar(255) not null, `scimUserId` varchar(36) not null references `scimUser` (`id`) on delete cascade, `userId` varchar(36) not null references `user` (`id`) on delete cascade, `sourceKind` text not null, `sourceId` text not null, `sourceValue` text, `role` text not null, `grantKey` varchar(255) not null unique, `createdAt` timestamp(3) not null, `updatedAt` timestamp(3) not null);

create table `scimGroup` (`id` varchar(36) not null primary key, `connectionId` varchar(255) not null, `provisioningDomainId` varchar(255) not null, `revision` integer not null, `displayName` text not null, `displayNameKey` varchar(255) not null unique, `externalId` text, `externalIdKey` varchar(255) unique, `orderKey` varchar(255) not null unique, `createdAt` timestamp(3) not null, `updatedAt` timestamp(3) not null);

create table `scimGroupMember` (`id` varchar(36) not null primary key, `connectionId` varchar(255) not null, `groupId` varchar(36) not null references `scimGroup` (`id`) on delete cascade, `scimUserId` varchar(36) not null references `scimUser` (`id`) on delete cascade, `membershipKey` varchar(255) not null unique, `createdAt` timestamp(3) not null);

create index `scimIdentityTombstone_connectionId_idx` on `scimIdentityTombstone` (`connectionId`);

create index `scimIdentityTombstone_provisioningDomainId_idx` on `scimIdentityTombstone` (`provisioningDomainId`);

create index `scimIdentityTombstone_userId_idx` on `scimIdentityTombstone` (`userId`);

create index `scimSubject_profileSourceId_idx` on `scimSubject` (`profileSourceId`);

create index `scimUser_connectionId_idx` on `scimUser` (`connectionId`);

create index `scimUser_provisioningDomainId_idx` on `scimUser` (`provisioningDomainId`);

create index `scimUser_userId_idx` on `scimUser` (`userId`);

create index `scimProjectionGrant_connectionId_idx` on `scimProjectionGrant` (`connectionId`);

create index `scimProjectionGrant_provisioningDomainId_idx` on `scimProjectionGrant` (`provisioningDomainId`);

create index `scimProjectionGrant_scimUserId_idx` on `scimProjectionGrant` (`scimUserId`);

create index `scimProjectionGrant_userId_idx` on `scimProjectionGrant` (`userId`);

create index `scimGroup_connectionId_idx` on `scimGroup` (`connectionId`);

create index `scimGroup_provisioningDomainId_idx` on `scimGroup` (`provisioningDomainId`);

create index `scimGroupMember_connectionId_idx` on `scimGroupMember` (`connectionId`);

create index `scimGroupMember_groupId_idx` on `scimGroupMember` (`groupId`);

create index `scimGroupMember_scimUserId_idx` on `scimGroupMember` (`scimUserId`);
