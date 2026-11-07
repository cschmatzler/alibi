-- Generated from Better Auth 1.7.18 by mysql-schema-assets.mjs.

create table `scimManagedConnection` (`id` varchar(36) not null primary key, `creationRequestId` varchar(255) not null unique, `connectionId` varchar(255) not null unique, `provisioningDomainId` varchar(255) not null, `status` text not null, `revision` integer not null, `createdAt` timestamp(3) not null, `createdBy` text not null, `decommissionStartedAt` timestamp(3), `decommissionStartedBy` text, `decommissionedAt` timestamp(3), `decommissionedBy` text);

create table `scimManagedCredential` (`id` varchar(36) not null primary key, `connectionRecordId` varchar(36) not null references `scimManagedConnection` (`id`) on delete cascade, `credentialId` varchar(255) not null unique, `tokenDigest` text not null, `hashVersion` text not null, `activeSlotKey` varchar(255) not null unique, `status` text not null, `serializedScopes` text not null, `expiresAt` timestamp(3) not null, `createdAt` timestamp(3) not null, `createdBy` text not null, `lastUsedAt` timestamp(3), `revokedAt` timestamp(3), `revokedBy` text, `decommissionedAt` timestamp(3));

create table `scimManagedConnectionEvent` (`id` varchar(36) not null primary key, `connectionRecordId` varchar(36) not null references `scimManagedConnection` (`id`) on delete cascade, `eventKey` varchar(255) not null unique, `sequence` integer not null, `type` text not null, `actorId` text not null, `credentialId` text, `createdAt` timestamp(3) not null);

create index `scimManagedConnection_provisioningDomainId_idx` on `scimManagedConnection` (`provisioningDomainId`);

create index `scimManagedCredential_connectionRecordId_idx` on `scimManagedCredential` (`connectionRecordId`);

create index `scimManagedConnectionEvent_connectionRecordId_idx` on `scimManagedConnectionEvent` (`connectionRecordId`);
