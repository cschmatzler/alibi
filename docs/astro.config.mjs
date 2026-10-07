import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: "https://alibi.schmatzler.com",
  // Pages that moved. Static redirects keep old links working.
  redirects: {
    '/guides/existing-databases': '/databases/existing-databases/',
    '/guides/passwordless-migration': '/plugins/email-otp/',
  },
  integrations: [
    starlight({
      title: 'Alibi',
      description: 'Alibi: authentication for Rust, compatible with Better Auth. Your database, your models, your stack.',
      favicon: '/favicon.svg',
      logo: { src: './src/assets/logo.svg', replacesTitle: false },
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/cschmatzler/better-auth-rs' },
      ],
      editLink: { baseUrl: 'https://github.com/cschmatzler/better-auth-rs/edit/main/docs/' },
      customCss: ['./src/styles/custom.css'],
      expressiveCode: { themes: ['github-dark', 'github-light'] },
      // Order matters: the sidebar is explicit so pages read in learning order
      // instead of alphabetically.
      sidebar: [
        {
          label: 'Get started',
          items: ['introduction', 'installation', 'basic-usage'],
        },
        {
          label: 'Concepts',
          items: [
            'concepts/database',
            'concepts/users-accounts',
            'concepts/session-management',
            'concepts/cookies',
            'concepts/field-policies',
            'concepts/security',
            'concepts/rate-limit',
            'concepts/secondary-storage',
            'concepts/plugins',
            'concepts/hooks',
            'concepts/notifications',
          ],
        },
        {
          label: 'Authentication',
          items: [
            'authentication/email-password',
            'authentication/email-verification',
            'authentication/social-sign-on',
            'authentication/generic-oauth',
          ],
        },
        {
          label: 'Databases',
          items: [
            'databases/sqlx',
            'databases/seaorm',
            'databases/existing-databases',
            'databases/no-database',
          ],
        },
        {
          label: 'Integrations',
          items: ['integrations/axum', 'integrations/poem', 'integrations/other-frameworks'],
        },
        {
          label: 'Plugins',
          items: [
            { label: 'Overview', slug: 'plugins' },
            {
              label: 'Sign-in methods',
              collapsed: true,
              items: [
                'plugins/username',
                'plugins/anonymous',
                'plugins/magic-link',
                'plugins/email-otp',
                'plugins/phone-number',
                'plugins/passkey',
                'plugins/siwe',
                'plugins/one-tap',
              ],
            },
            {
              label: 'OAuth and federation',
              collapsed: true,
              items: ['plugins/oauth-popup', 'plugins/oauth-proxy'],
            },
            {
              label: 'Multi-factor and devices',
              collapsed: true,
              items: ['plugins/two-factor', 'plugins/device-authorization'],
            },
            {
              label: 'Sessions and tokens',
              collapsed: true,
              items: [
                'plugins/bearer',
                'plugins/jwt',
                'plugins/one-time-token',
                'plugins/multi-session',
                'plugins/custom-session',
                'plugins/last-login-method',
              ],
            },
            {
              label: 'Machine access',
              collapsed: true,
              items: ['plugins/api-key'],
            },
            {
              label: 'Hardening',
              collapsed: true,
              items: ['plugins/captcha', 'plugins/have-i-been-pwned'],
            },
            {
              label: 'Administration',
              collapsed: true,
              items: ['plugins/admin', 'plugins/organization'],
            },
            {
              label: 'Developer tools',
              collapsed: true,
              items: ['plugins/open-api'],
            },
          ],
        },
        {
          label: 'Guides',
          items: [
            'guides/cross-origin',
            'guides/server-side-calls',
            'guides/writing-a-plugin',
            'guides/legacy-oauth-tokens',
          ],
        },
        {
          label: 'Frontend (official docs)',
          items: [
            { label: 'Client setup', link: 'https://www.better-auth.com/docs/concepts/client' },
            { label: 'Client usage', link: 'https://www.better-auth.com/docs/basic-usage' },
            { label: 'Client plugins', link: 'https://www.better-auth.com/docs/concepts/client#plugins' },
          ],
        },
        {
          label: 'Reference',
          items: [
            'reference/options',
            'reference/http-api',
            'reference/errors',
            'reference/cli',
            'reference/features',
            'reference/secrets',
            'reference/telemetry',
          ],
        },
        {
          label: 'Project',
          items: [
            'reference/compatibility',
            'reference/crates',
            'guides/development',
            'guides/releases',
          ],
        },
      ],
    }),
  ],
});
