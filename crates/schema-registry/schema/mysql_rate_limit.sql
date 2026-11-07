-- Generated from Better Auth 1.7.18 by mysql-schema-assets.mjs.

create table `rateLimit` (`id` varchar(36) not null primary key, `key` varchar(255) not null unique, `count` integer not null, `lastRequest` bigint not null);
