import { betterAuth } from 'better-auth';
import { createAuthEndpoint, createAuthMiddleware } from 'better-auth/api';
import { Database } from 'bun:sqlite';
import { getMigrations } from 'better-auth/db/migration';
const db = new Database(':memory:');
const events: string[] = [];
const auth = betterAuth({
  database: db, secret: 'lifecycle181-private-secret-length-32',
  baseURL: 'http://localhost:31981', logger: { disabled: true },
  plugins: [
    { id: 'committing-writer', endpoints: {
      callbackError: createAuthEndpoint('/callback-error', { method: 'GET' }, async c => {
        const mode = c.headers?.get('x-mode');
        if (mode === 'success') return new Response(null, { status: 204 });
        await c.context.internalAdapter.createUser({email: `${mode}@lifecycle.fixture.test`, name: mode!, emailVerified: false});
        events.push('committed');
        c.setHeader('x-queued', 'private-header');
        c.setCookie('queued', 'value', {httpOnly: true, path: '/'}); c.setCookie('second', 'value', {httpOnly: true, path: '/'});
        if (mode === 'api') throw c.error('FORBIDDEN', { message: 'explicit' });
        throw new Error('private application cause');
      })
    } },
    { id: 'completed-observer', hooks: { after: [{ matcher: () => true,
      handler: createAuthMiddleware(async () => { events.push('after'); }) }] } }
  ]
});
await (await getMigrations(auth.options)).runMigrations();
for (const mode of ['api', 'ordinary', 'success']) {
  events.length = 0;
  const response = await auth.handler(new Request('http://localhost:31981/api/auth/callback-error', { headers: {'x-mode': mode} }));
  console.log(JSON.stringify({mode, status: response.status, headers: [...response.headers], body: await response.text(), events: [...events], users: db.query('SELECT email FROM user ORDER BY email').all()}));
}
