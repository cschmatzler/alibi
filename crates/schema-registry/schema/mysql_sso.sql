-- Generated from Better Auth 1.7.18 by mysql-schema-assets.mjs.

create table `ssoProvider` (`id` varchar(36) not null primary key, `issuer` text not null, `oidcConfig` text, `samlConfig` text, `userId` varchar(36) not null references `user` (`id`) on delete cascade, `providerId` varchar(255) not null unique, `organizationId` text, `domain` text not null, `domainVerified` boolean);
