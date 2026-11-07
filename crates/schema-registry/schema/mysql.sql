-- Generated from Better Auth 1.7.18 by mysql-schema-assets.mjs.

create table `user` (`id` varchar(36) not null primary key, `name` varchar(255) not null, `email` varchar(255) not null unique, `emailVerified` boolean not null, `image` text, `createdAt` timestamp(3) default CURRENT_TIMESTAMP(3) not null, `updatedAt` timestamp(3) default CURRENT_TIMESTAMP(3) not null, `role` text, `banned` boolean, `banReason` text, `banExpires` timestamp(3), `isAnonymous` boolean, `phoneNumber` varchar(255) unique, `phoneNumberVerified` boolean, `lastLoginMethod` text, `username` varchar(255) unique, `displayUsername` text, `twoFactorEnabled` boolean);

create table `session` (`id` varchar(36) not null primary key, `expiresAt` timestamp(3) not null, `token` varchar(255) not null unique, `createdAt` timestamp(3) default CURRENT_TIMESTAMP(3) not null, `updatedAt` timestamp(3) not null, `ipAddress` text, `userAgent` text, `userId` varchar(36) not null references `user` (`id`) on delete cascade, `impersonatedBy` text, `activeOrganizationId` text, `activeTeamId` text);

create table `account` (`id` varchar(36) not null primary key, `accountId` text not null, `providerId` text not null, `userId` varchar(36) not null references `user` (`id`) on delete cascade, `accessToken` text, `refreshToken` text, `idToken` text, `accessTokenExpiresAt` timestamp(3), `refreshTokenExpiresAt` timestamp(3), `scope` text, `password` text, `createdAt` timestamp(3) default CURRENT_TIMESTAMP(3) not null, `updatedAt` timestamp(3) not null);

create table `verification` (`id` varchar(36) not null primary key, `identifier` varchar(255) not null, `value` text not null, `expiresAt` timestamp(3) not null, `createdAt` timestamp(3) default CURRENT_TIMESTAMP(3) not null, `updatedAt` timestamp(3) default CURRENT_TIMESTAMP(3) not null);

create table `organization` (`id` varchar(36) not null primary key, `name` varchar(255) not null, `slug` varchar(255) not null unique, `logo` text, `createdAt` timestamp(3) not null, `metadata` text);

create table `organizationRole` (`id` varchar(36) not null primary key, `organizationId` varchar(36) not null references `organization` (`id`) on delete cascade, `role` varchar(255) not null, `permission` text not null, `createdAt` timestamp(3) default CURRENT_TIMESTAMP(3) not null, `updatedAt` timestamp(3));

create table `team` (`id` varchar(36) not null primary key, `name` text not null, `memberCount` integer not null, `organizationId` varchar(36) not null references `organization` (`id`) on delete cascade, `createdAt` timestamp(3) not null, `updatedAt` timestamp(3));

create table `teamMember` (`id` varchar(36) not null primary key, `teamId` varchar(36) not null references `team` (`id`) on delete cascade, `userId` varchar(36) not null references `user` (`id`) on delete cascade, `membershipKey` varchar(255) unique, `createdAt` timestamp(3));

create table `member` (`id` varchar(36) not null primary key, `organizationId` varchar(36) not null references `organization` (`id`) on delete cascade, `userId` varchar(36) not null references `user` (`id`) on delete cascade, `role` varchar(255) not null, `createdAt` timestamp(3) not null);

create table `invitation` (`id` varchar(36) not null primary key, `organizationId` varchar(36) not null references `organization` (`id`) on delete cascade, `email` varchar(255) not null, `role` varchar(255), `teamId` varchar(255), `status` varchar(255) not null, `expiresAt` timestamp(3) not null, `createdAt` timestamp(3) default CURRENT_TIMESTAMP(3) not null, `inviterId` varchar(36) not null references `user` (`id`) on delete cascade);

create table `twoFactor` (`id` varchar(36) not null primary key, `secret` varchar(255) not null, `backupCodes` text not null, `userId` varchar(36) not null references `user` (`id`) on delete cascade, `verified` boolean, `failedVerificationCount` integer, `lockedUntil` timestamp(3));

create table `deviceCode` (`id` varchar(36) not null primary key, `deviceCode` varchar(191) not null, `userCode` varchar(191) not null, `userId` text, `expiresAt` timestamp(3) not null, `status` text not null, `lastPolledAt` timestamp(3), `pollingInterval` integer, `clientId` text, `scope` text);

create table `jwks` (`id` varchar(36) not null primary key, `publicKey` text not null, `privateKey` text not null, `createdAt` timestamp(3) not null, `expiresAt` timestamp(3), `alg` text, `crv` text);

create table `walletAddress` (`id` varchar(36) not null primary key, `userId` varchar(36) not null references `user` (`id`) on delete cascade, `address` text not null, `chainId` integer not null, `isPrimary` boolean not null, `createdAt` timestamp(3) not null);

create table `apikey` (`id` varchar(36) not null primary key, `configId` varchar(255) not null, `name` text, `start` text, `referenceId` varchar(255) not null, `prefix` text, `key` varchar(255) not null, `refillInterval` integer, `refillAmount` integer, `lastRefillAt` timestamp(3), `enabled` boolean, `rateLimitEnabled` boolean, `rateLimitTimeWindow` integer, `rateLimitMax` integer, `requestCount` integer, `remaining` integer, `lastRequest` timestamp(3), `expiresAt` timestamp(3), `createdAt` timestamp(3) not null, `updatedAt` timestamp(3) not null, `permissions` text, `metadata` text);

create table `passkey` (`id` varchar(36) not null primary key, `name` text, `publicKey` text not null, `userId` varchar(36) not null references `user` (`id`) on delete cascade, `credentialID` varchar(255) not null, `counter` integer not null, `deviceType` text not null, `backedUp` boolean not null, `transports` text, `createdAt` timestamp(3), `aaguid` text);

create index `session_userId_idx` on `session` (`userId`);

create index `account_userId_idx` on `account` (`userId`);

create index `verification_identifier_idx` on `verification` (`identifier`);

create index `organizationRole_organizationId_idx` on `organizationRole` (`organizationId`);

create index `organizationRole_role_idx` on `organizationRole` (`role`);

create index `team_organizationId_idx` on `team` (`organizationId`);

create index `teamMember_teamId_idx` on `teamMember` (`teamId`);

create index `teamMember_userId_idx` on `teamMember` (`userId`);

create index `member_organizationId_idx` on `member` (`organizationId`);

create index `member_userId_idx` on `member` (`userId`);

create index `invitation_organizationId_idx` on `invitation` (`organizationId`);

create index `invitation_email_idx` on `invitation` (`email`);

create index `twoFactor_secret_idx` on `twoFactor` (`secret`);

create index `twoFactor_userId_idx` on `twoFactor` (`userId`);

create index `walletAddress_userId_idx` on `walletAddress` (`userId`);

create index `apikey_configId_idx` on `apikey` (`configId`);

create index `apikey_referenceId_idx` on `apikey` (`referenceId`);

create index `apikey_key_idx` on `apikey` (`key`);

create index `passkey_userId_idx` on `passkey` (`userId`);

create index `passkey_credentialID_idx` on `passkey` (`credentialID`);

create unique index `deviceCode_deviceCode_uidx` on `deviceCode` (`deviceCode`);

create unique index `deviceCode_userCode_uidx` on `deviceCode` (`userCode`);
