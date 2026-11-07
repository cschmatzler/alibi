-- Generated from Better Auth 1.7.18 by mysql-schema-assets.mjs.

create table `scimConnectionBinding` (`id` varchar(36) not null primary key, `connectionId` varchar(255) not null, `connectionKey` varchar(255) not null unique, `provisioningDomainId` text not null, `createdAt` timestamp(3) not null, `decommissionedAt` timestamp(3), `decommissionStatus` text not null, `decommissionCursorUserId` text, `decommissionReconciledUserCount` integer not null, `decommissionBatchCount` integer not null, `decommissionRevision` integer not null, `decommissionCompletedAt` timestamp(3), `decommissionLeaseId` text, `decommissionLeaseExpiresAt` timestamp(3));

create index `scimConnectionBinding_connectionId_idx` on `scimConnectionBinding` (`connectionId`);
