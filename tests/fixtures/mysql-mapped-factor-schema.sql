create table `user` (`id` varchar(36) not null primary key, `name` varchar(255) not null, `email` varchar(255) not null unique, `emailVerified` boolean not null, `image` text, `createdAt` timestamp(3) default CURRENT_TIMESTAMP(3) not null, `updatedAt` timestamp(3) default CURRENT_TIMESTAMP(3) not null, `role` text, `banned` boolean, `banReason` text, `banExpires` timestamp(3), `isAnonymous` boolean, `phoneNumber` varchar(255) unique, `phoneNumberVerified` boolean, `lastLoginMethod` text, `username` varchar(255) unique, `displayUsername` text, `twoFactorEnabled` boolean);

create table `session` (`id` varchar(36) not null primary key, `expiresAt` timestamp(3) not null, `token` varchar(255) not null unique, `createdAt` timestamp(3) default CURRENT_TIMESTAMP(3) not null, `updatedAt` timestamp(3) not null, `ipAddress` text, `userAgent` text, `userId` varchar(36) not null references `user` (`id`) on delete cascade, `impersonatedBy` text, `activeOrganizationId` text, `activeTeamId` text);

create table `account` (`id` varchar(36) not null primary key, `accountId` text not null, `providerId` text not null, `userId` varchar(36) not null references `user` (`id`) on delete cascade, `accessToken` text, `refreshToken` text, `idToken` text, `accessTokenExpiresAt` timestamp(3), `refreshTokenExpiresAt` timestamp(3), `scope` text, `password` text, `createdAt` timestamp(3) default CURRENT_TIMESTAMP(3) not null, `updatedAt` timestamp(3) not null);

create table `verification` (`id` varchar(36) not null primary key, `identifier` varchar(255) not null, `value` text not null, `expiresAt` timestamp(3) not null, `createdAt` timestamp(3) default CURRENT_TIMESTAMP(3) not null, `updatedAt` timestamp(3) default CURRENT_TIMESTAMP(3) not null);

create table `ssoProvider` (`id` varchar(36) not null primary key, `issuer` text not null, `oidcConfig` text, `samlConfig` text, `userId` varchar(36) not null references `user` (`id`) on delete cascade, `providerId` varchar(255) not null unique, `organizationId` text, `domain` text not null, `domainVerified` boolean);

create table `organization` (`id` varchar(36) not null primary key, `name` varchar(255) not null, `slug` varchar(255) not null unique, `logo` text, `createdAt` timestamp(3) not null, `metadata` text);

create table `organizationRole` (`id` varchar(36) not null primary key, `organizationId` varchar(36) not null references `organization` (`id`) on delete cascade, `role` varchar(255) not null, `permission` text not null, `createdAt` timestamp(3) default CURRENT_TIMESTAMP(3) not null, `updatedAt` timestamp(3));

create table `team` (`id` varchar(36) not null primary key, `name` text not null, `memberCount` integer not null, `organizationId` varchar(36) not null references `organization` (`id`) on delete cascade, `createdAt` timestamp(3) not null, `updatedAt` timestamp(3));

create table `teamMember` (`id` varchar(36) not null primary key, `teamId` varchar(36) not null references `team` (`id`) on delete cascade, `userId` varchar(36) not null references `user` (`id`) on delete cascade, `membershipKey` varchar(255) unique, `createdAt` timestamp(3));

create table `member` (`id` varchar(36) not null primary key, `organizationId` varchar(36) not null references `organization` (`id`) on delete cascade, `userId` varchar(36) not null references `user` (`id`) on delete cascade, `role` varchar(255) not null, `createdAt` timestamp(3) not null);

create table `invitation` (`id` varchar(36) not null primary key, `organizationId` varchar(36) not null references `organization` (`id`) on delete cascade, `email` varchar(255) not null, `role` varchar(255), `teamId` varchar(255), `status` varchar(255) not null, `expiresAt` timestamp(3) not null, `createdAt` timestamp(3) default CURRENT_TIMESTAMP(3) not null, `inviterId` varchar(36) not null references `user` (`id`) on delete cascade);

create table `factor_records` (`id` varchar(36) not null primary key, `factor_secret` varchar(255) not null, `backup_codes` text not null, `owner_id` varchar(36) not null references `user` (`id`) on delete cascade, `is_verified` boolean, `failure_count` integer, `locked_until` timestamp(3));

create table `deviceCode` (`id` varchar(36) not null primary key, `deviceCode` varchar(191) not null, `userCode` varchar(191) not null, `userId` text, `expiresAt` timestamp(3) not null, `status` text not null, `lastPolledAt` timestamp(3), `pollingInterval` integer, `clientId` text, `scope` text);

create table `jwks` (`id` varchar(36) not null primary key, `publicKey` text not null, `privateKey` text not null, `createdAt` timestamp(3) not null, `expiresAt` timestamp(3), `alg` text, `crv` text);

create table `walletAddress` (`id` varchar(36) not null primary key, `userId` varchar(36) not null references `user` (`id`) on delete cascade, `address` text not null, `chainId` integer not null, `isPrimary` boolean not null, `createdAt` timestamp(3) not null);

create table `apikey` (`id` varchar(36) not null primary key, `configId` varchar(255) not null, `name` text, `start` text, `referenceId` varchar(255) not null, `prefix` text, `key` varchar(255) not null, `refillInterval` integer, `refillAmount` integer, `lastRefillAt` timestamp(3), `enabled` boolean, `rateLimitEnabled` boolean, `rateLimitTimeWindow` integer, `rateLimitMax` integer, `requestCount` integer, `remaining` integer, `lastRequest` timestamp(3), `expiresAt` timestamp(3), `createdAt` timestamp(3) not null, `updatedAt` timestamp(3) not null, `permissions` text, `metadata` text);

create table `passkey` (`id` varchar(36) not null primary key, `name` text, `publicKey` text not null, `userId` varchar(36) not null references `user` (`id`) on delete cascade, `credentialID` varchar(255) not null, `counter` integer not null, `deviceType` text not null, `backedUp` boolean not null, `transports` text, `createdAt` timestamp(3), `aaguid` text);

create table `oauthClient` (`id` varchar(36) not null primary key, `clientId` varchar(255) not null unique, `clientSecret` text, `clientDiscoveryId` text, `disabled` boolean, `skipConsent` boolean, `enableEndSession` boolean, `subjectType` text, `scopes` json, `clientCredentialsScopes` json, `userId` varchar(36) references `user` (`id`) on delete cascade, `createdAt` timestamp(3), `updatedAt` timestamp(3), `name` text, `uri` text, `icon` text, `contacts` json, `tos` text, `policy` text, `softwareId` text, `softwareVersion` text, `softwareStatement` text, `redirectUris` json not null, `postLogoutRedirectUris` json, `backchannelLogoutUri` text, `backchannelLogoutSessionRequired` boolean, `tokenEndpointAuthMethod` text, `applicationType` text, `jwks` text, `jwksUri` text, `grantTypes` json, `responseTypes` json, `requirePKCE` boolean, `dpopBoundAccessTokens` boolean, `referenceId` text, `metadata` json);

create table `oauthResource` (`id` varchar(36) not null primary key, `identifier` varchar(255) not null unique, `name` text not null, `accessTokenTtl` integer, `refreshTokenTtl` integer, `signingAlgorithm` text, `signingKeyId` text, `allowedScopes` json, `customClaims` json, `dpopBoundAccessTokensRequired` boolean, `disabled` boolean, `createdAt` timestamp(3), `updatedAt` timestamp(3), `policyVersion` integer, `metadata` json);

create table `oauthClientResource` (`id` varchar(36) not null primary key, `clientId` varchar(191) not null references `oauthClient` (`clientId`) on delete cascade, `resourceId` varchar(191) not null references `oauthResource` (`identifier`) on delete cascade, `metadata` json, `createdAt` timestamp(3));

create table `oauthRefreshToken` (`id` varchar(36) not null primary key, `token` varchar(255) not null unique, `clientId` varchar(36) not null references `oauthClient` (`clientId`) on delete cascade, `sessionId` varchar(36) references `session` (`id`) on delete set null, `userId` varchar(36) not null references `user` (`id`) on delete cascade, `referenceId` text, `authorizationCodeId` varchar(255), `resources` json, `requestedUserInfoClaims` json, `expiresAt` timestamp(3) not null, `createdAt` timestamp(3) not null, `revoked` timestamp(3), `rotatedAt` timestamp(3), `rotationReplayResponse` text, `rotationReplayExpiresAt` timestamp(3), `authTime` timestamp(3), `confirmation` json, `scopes` json not null);

create table `oauthAccessToken` (`id` varchar(36) not null primary key, `token` varchar(255) not null unique, `clientId` varchar(36) not null references `oauthClient` (`clientId`) on delete cascade, `sessionId` varchar(36) references `session` (`id`) on delete set null, `userId` varchar(36) references `user` (`id`) on delete cascade, `referenceId` text, `authorizationCodeId` varchar(255), `resources` json, `requestedUserInfoClaims` json, `refreshId` varchar(36) references `oauthRefreshToken` (`id`) on delete cascade, `expiresAt` timestamp(3) not null, `createdAt` timestamp(3) not null, `revoked` timestamp(3), `confirmation` json, `scopes` json not null);

create table `oauthConsent` (`id` varchar(36) not null primary key, `clientId` varchar(36) not null references `oauthClient` (`clientId`) on delete cascade, `userId` varchar(36) references `user` (`id`) on delete cascade, `referenceId` text, `resources` json, `requestedUserInfoClaims` json, `scopes` json not null, `createdAt` timestamp(3) not null, `updatedAt` timestamp(3) not null);

create table `oauthClientAssertion` (`id` varchar(36) not null primary key, `expiresAt` timestamp(3) not null);

create table `rateLimit` (`id` varchar(36) not null primary key, `key` varchar(255) not null unique, `count` integer not null, `lastRequest` bigint not null);

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

create index `factor_records_factor_secret_idx` on `factor_records` (`factor_secret`);

create index `factor_records_owner_id_idx` on `factor_records` (`owner_id`);

create index `walletAddress_userId_idx` on `walletAddress` (`userId`);

create index `apikey_configId_idx` on `apikey` (`configId`);

create index `apikey_referenceId_idx` on `apikey` (`referenceId`);

create index `apikey_key_idx` on `apikey` (`key`);

create index `passkey_userId_idx` on `passkey` (`userId`);

create index `passkey_credentialID_idx` on `passkey` (`credentialID`);

create index `oauthClient_userId_idx` on `oauthClient` (`userId`);

create index `oauthClientResource_clientId_idx` on `oauthClientResource` (`clientId`);

create index `oauthClientResource_resourceId_idx` on `oauthClientResource` (`resourceId`);

create index `oauthRefreshToken_clientId_idx` on `oauthRefreshToken` (`clientId`);

create index `oauthRefreshToken_sessionId_idx` on `oauthRefreshToken` (`sessionId`);

create index `oauthRefreshToken_userId_idx` on `oauthRefreshToken` (`userId`);

create index `oauthRefreshToken_authorizationCodeId_idx` on `oauthRefreshToken` (`authorizationCodeId`);

create index `oauthAccessToken_clientId_idx` on `oauthAccessToken` (`clientId`);

create index `oauthAccessToken_sessionId_idx` on `oauthAccessToken` (`sessionId`);

create index `oauthAccessToken_userId_idx` on `oauthAccessToken` (`userId`);

create index `oauthAccessToken_authorizationCodeId_idx` on `oauthAccessToken` (`authorizationCodeId`);

create index `oauthAccessToken_refreshId_idx` on `oauthAccessToken` (`refreshId`);

create index `oauthConsent_clientId_idx` on `oauthConsent` (`clientId`);

create index `oauthConsent_userId_idx` on `oauthConsent` (`userId`);

create unique index `deviceCode_deviceCode_uidx` on `deviceCode` (`deviceCode`);

create unique index `deviceCode_userCode_uidx` on `deviceCode` (`userCode`);

create unique index `oauthClientResource_clientId_resourceId_uidx` on `oauthClientResource` (`clientId`, `resourceId`);
