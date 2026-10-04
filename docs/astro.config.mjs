import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: "https://better-auth-rs.schmatzler.com",
  integrations: [
    starlight({
      title: 'Better Auth RS',
      description: 'Better Auth for Rust. Authentication, your database, your stack.',
      favicon: '/favicon.svg',
      logo: { src: './src/assets/logo.svg', replacesTitle: false },
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/cschmatzler/better-auth-rs' },
      ],
      editLink: { baseUrl: 'https://github.com/cschmatzler/better-auth-rs/edit/main/docs/' },
      customCss: ['./src/styles/custom.css'],
      expressiveCode: { themes: ['github-dark', 'github-light'] },
      sidebar: [
        {
          label: 'Get started',
          items: ['introduction', 'installation', 'basic-usage'],
        },
        {
          label: 'Concepts',
          items: [
            'concepts/database', 'concepts/users-accounts',
            'concepts/session-management', 'concepts/cookies',
            'concepts/secondary-storage', 'concepts/plugins', 'concepts/hooks',
            'concepts/field-policies', 'concepts/notifications', 'concepts/rate-limit',
          ],
        },
        { label: 'Authentication', items: [{ autogenerate: { directory: 'authentication' } }] },
        { label: 'Databases', items: [{ autogenerate: { directory: 'databases' } }] },
        { label: 'Integrations', items: [{ autogenerate: { directory: 'integrations' } }] },
        { label: 'Plugins', collapsed: true, items: [{ autogenerate: { directory: 'plugins' } }] },
        { label: 'Guides', collapsed: true, items: [{ autogenerate: { directory: 'guides' } }] },
        {
          label: 'Frontend (official docs)',
          items: [
            { label: 'Client setup', link: 'https://www.better-auth.com/docs/concepts/client' },
            { label: 'Client usage', link: 'https://www.better-auth.com/docs/basic-usage' },
            { label: 'Client plugins', link: 'https://www.better-auth.com/docs/concepts/client#plugins' },
          ],
        },
        { label: 'Reference', collapsed: true, items: [{ autogenerate: { directory: 'reference' } }] },
      ],
    }),
  ],
});
