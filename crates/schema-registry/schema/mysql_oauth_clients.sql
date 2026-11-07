-- Generated from Better Auth 1.7.18 by mysql-schema-assets.mjs.

create table `oauthClient` (`id` varchar(36) not null primary key, `clientId` varchar(255) not null unique, `clientSecret` text, `clientDiscoveryId` text, `disabled` boolean, `skipConsent` boolean, `enableEndSession` boolean, `subjectType` text, `scopes` json, `clientCredentialsScopes` json, `userId` varchar(36) references `user` (`id`) on delete cascade, `createdAt` timestamp(3), `updatedAt` timestamp(3), `name` text, `uri` text, `icon` text, `contacts` json, `tos` text, `policy` text, `softwareId` text, `softwareVersion` text, `softwareStatement` text, `redirectUris` json not null, `postLogoutRedirectUris` json, `backchannelLogoutUri` text, `backchannelLogoutSessionRequired` boolean, `tokenEndpointAuthMethod` text, `applicationType` text, `jwks` text, `jwksUri` text, `grantTypes` json, `responseTypes` json, `requirePKCE` boolean, `dpopBoundAccessTokens` boolean, `referenceId` text, `metadata` json);

create table `oauthResource` (`id` varchar(36) not null primary key, `identifier` varchar(255) not null unique, `name` text not null, `accessTokenTtl` integer, `refreshTokenTtl` integer, `signingAlgorithm` text, `signingKeyId` text, `allowedScopes` json, `customClaims` json, `dpopBoundAccessTokensRequired` boolean, `disabled` boolean, `createdAt` timestamp(3), `updatedAt` timestamp(3), `policyVersion` integer, `metadata` json);

create table `oauthClientResource` (`id` varchar(36) not null primary key, `clientId` varchar(191) not null references `oauthClient` (`clientId`) on delete cascade, `resourceId` varchar(191) not null references `oauthResource` (`identifier`) on delete cascade, `metadata` json, `createdAt` timestamp(3));

create table `oauthRefreshToken` (`id` varchar(36) not null primary key, `token` varchar(255) not null unique, `clientId` varchar(36) not null references `oauthClient` (`clientId`) on delete cascade, `sessionId` varchar(36) references `session` (`id`) on delete set null, `userId` varchar(36) not null references `user` (`id`) on delete cascade, `referenceId` text, `authorizationCodeId` varchar(255), `resources` json, `requestedUserInfoClaims` json, `expiresAt` timestamp(3) not null, `createdAt` timestamp(3) not null, `revoked` timestamp(3), `rotatedAt` timestamp(3), `rotationReplayResponse` text, `rotationReplayExpiresAt` timestamp(3), `authTime` timestamp(3), `confirmation` json, `scopes` json not null);

create table `oauthAccessToken` (`id` varchar(36) not null primary key, `token` varchar(255) not null unique, `clientId` varchar(36) not null references `oauthClient` (`clientId`) on delete cascade, `sessionId` varchar(36) references `session` (`id`) on delete set null, `userId` varchar(36) references `user` (`id`) on delete cascade, `referenceId` text, `authorizationCodeId` varchar(255), `resources` json, `requestedUserInfoClaims` json, `refreshId` varchar(36) references `oauthRefreshToken` (`id`) on delete cascade, `expiresAt` timestamp(3) not null, `createdAt` timestamp(3) not null, `revoked` timestamp(3), `confirmation` json, `scopes` json not null);

create table `oauthConsent` (`id` varchar(36) not null primary key, `clientId` varchar(36) not null references `oauthClient` (`clientId`) on delete cascade, `userId` varchar(36) references `user` (`id`) on delete cascade, `referenceId` text, `resources` json, `requestedUserInfoClaims` json, `scopes` json not null, `createdAt` timestamp(3) not null, `updatedAt` timestamp(3) not null);

create table `oauthClientAssertion` (`id` varchar(36) not null primary key, `expiresAt` timestamp(3) not null);

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

create unique index `oauthClientResource_clientId_resourceId_uidx` on `oauthClientResource` (`clientId`, `resourceId`);
