-- Generated from Better Auth 1.7.7 by the schema parity probe.

create table "rateLimit" ("id" text not null primary key, "key" text not null unique, "count" integer not null, "lastRequest" bigint not null);
