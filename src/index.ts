import { createAI } from 'agents';

// -----------------------------------------------------------------------------
// Tipos
// -----------------------------------------------------------------------------
interface Env {
  USER_SESSION: DurableObjectNamespace;
  ARTEFACTOOL: DurableObjectNamespace;
  VAULT: DurableObjectNamespace;
  LOADER: WorkerLoader;
  AI: any;
  ASSETS: Fetcher;
}

interface MessageRow {
  id: number;
  role: string;
  content: string;
  created_at: number;
}

// -----------------------------------------------------------------------------
// Durable Object: UserSessionDO — orquestador conversacional por usuario
// -----------------------------------------------------------------------------
export class UserSessionDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        role TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
    `);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS artefactools (
        instance_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
    `);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // GET /v1/messages — historial de la sesión
    if (url.pathname === '/v1/messages' && request.method === 'GET') {
      const cursor = this.ctx.storage.sql.exec(
        'SELECT id, role, content, created_at FROM messages ORDER BY id DESC LIMIT 100'
      );
      const messages: MessageRow[] = [];
      for (const row of cursor) {
        const v = row.value as unknown as [number, string, string, number];
        messages.push({ id: v[0], role: v[1], content: v[2], created_at: v[3] });
      }
      return Response.json({ ok: true, messages });
    }

    // POST /v1/messages — guardar un mensaje de la sesión
    if (url.pathname === '/v1/messages' && request.method === 'POST') {
      try {
        const body = (await request.json()) as { role?: string; content?: string };
        if (!body.role || !body.content) {
          return Response.json({ ok: false, error: 'role and content required' }, { status: 400 });
        }
        this.ctx.storage.sql.exec(
          'INSERT INTO messages (role, content, created_at) VALUES (?, ?, ?)',
          [body.role, body.content, Date.now()]
        );
        return Response.json({ ok: true });
      } catch {
        return Response.json({ ok: false, error: 'invalid json' }, { status: 400 });
      }
    }

    // GET /v1/artefactools — listar artefactools activadas del usuario
    if (url.pathname === '/v1/artefactools' && request.method === 'GET') {
      const cursor = this.ctx.storage.sql.exec(
        'SELECT instance_id, name, created_at FROM artefactools ORDER BY created_at DESC'
      );
      const items: { instance_id: string; name: string; created_at: number }[] = [];
      for (const row of cursor) {
        const v = row.value as unknown as [string, string, number];
        items.push({ instance_id: v[0], name: v[1], created_at: v[2] });
      }
      return Response.json({ ok: true, items });
    }

    // POST /v1/artefactools — activar una artefactool
    if (url.pathname === '/v1/artefactools' && request.method === 'POST') {
      try {
        const body = (await request.json()) as { name?: string };
        if (!body.name) {
          return Response.json({ ok: false, error: 'name required' }, { status: 400 });
        }
        const id = this.env.ARTEFACTOOL.idFromName(body.name);
        const stub = this.env.ARTEFACTOOL.get(id);
        await stub.fetch('https://internal/artefactool/init', { method: 'POST' });
        this.ctx.storage.sql.exec(
          'INSERT OR REPLACE INTO artefactools (instance_id, name, created_at) VALUES (?, ?, ?)',
          [id.toString(), body.name, Date.now()]
        );
        return Response.json({ ok: true, instance_id: id.toString(), name: body.name });
      } catch (e) {
        return Response.json({ ok: false, error: String(e) }, { status: 500 });
      }
    }

    return new Response('not found', { status: 404 });
  }
}

// -----------------------------------------------------------------------------
// Durable Object: ArtefactoolDO — instancia aislada por herramienta activada
// -----------------------------------------------------------------------------
export class ArtefactoolDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );
    `);
    this.ctx.storage.sql.exec(
      'INSERT OR REPLACE INTO state (key, value, updated_at) VALUES (?, ?, ?)',
      ['initialized', 'true', String(Date.now())]
    );
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/v1/state' && request.method === 'GET') {
      const cursor = this.ctx.storage.sql.exec('SELECT key, value, updated_at FROM state');
      const items: Record<string, string> = {};
      for (const row of cursor) {
        const v = row.value as unknown as [string, string];
        items[v[0]] = v[1];
      }
      return Response.json({ ok: true, state: items });
    }

    if (url.pathname === '/v1/state' && request.method === 'POST') {
      try {
        const body = (await request.json()) as { key?: string; value?: string };
        if (!body.key || body.value === undefined) {
          return Response.json({ ok: false, error: 'key and value required' }, { status: 400 });
        }
        this.ctx.storage.sql.exec(
          'INSERT OR REPLACE INTO state (key, value, updated_at) VALUES (?, ?, ?)',
          [body.key, String(body.value), String(Date.now())]
        );
        return Response.json({ ok: true });
      } catch {
        return Response.json({ ok: false, error: 'invalid json' }, { status: 400 });
      }
    }

    if (url.pathname === '/v1/execute' && request.method === 'POST') {
      // Ejecución aislada de código ligero vía Worker Loader (sandbox V8)
      try {
        const body = (await request.json()) as { code?: string };
        if (!body.code) {
          return Response.json({ ok: false, error: 'code required' }, { status: 400 });
        }
        const mod = await this.env.LOADER.load({ module: { text: body.code } });
        const result = await mod.exports.default?.({});
        return Response.json({ ok: true, result });
      } catch (e) {
        return Response.json({ ok: false, error: String(e) }, { status: 500 });
      }
    }

    return new Response('not found', { status: 404 });
  }
}

// -----------------------------------------------------------------------------
// Durable Object: CredentialVaultDO — bóveda de credenciales (zero-leak)
// -----------------------------------------------------------------------------
export class CredentialVaultDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS credentials (
        service TEXT PRIMARY KEY,
        encrypted_value TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );
    `);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS approvals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service TEXT NOT NULL,
        action TEXT NOT NULL,
        payload TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at INTEGER NOT NULL
      );
    `);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // GET /v1/vault/credentials — listar servicios configurados (sin valores)
    if (url.pathname.startsWith('/v1/vault/credentials') && request.method === 'GET') {
      const cursor = this.ctx.storage.sql.exec('SELECT service, updated_at FROM credentials');
      const services: { service: string; updated_at: number }[] = [];
      for (const row of cursor) {
        const v = row.value as unknown as [string, number];
        services.push({ service: v[0], updated_at: v[1] });
      }
      return Response.json({ ok: true, services });
    }

    // POST /v1/vault/execute — inyectar credencial y llamar al servicio externo
    // El LLM nunca ve la clave: la Bóveda la recupera, la inyecta y devuelve solo la respuesta.
    if (url.pathname === '/v1/vault/execute' && request.method === 'POST') {
      try {
        const body = (await request.json()) as {
          service?: string;
          method?: string;
          path?: string;
          body?: any;
          requires_approval?: boolean;
        };
        if (!body.service) {
          return Response.json({ ok: false, error: 'service required' }, { status: 400 });
        }

        const cursor = this.ctx.storage.sql.exec(
          'SELECT encrypted_value FROM credentials WHERE service = ?',
          [body.service]
        );
        let cred: string | null = null;
        for (const row of cursor) {
          const v = row.value as unknown as [string];
          cred = v[0];
        }

        if (body.requires_approval && cred === null) {
          return Response.json(
            { ok: false, error: 'credential not found; approval required to store first' },
            { status: 403 }
          );
        }

        // Resolver credencial (desencriptar en un entorno real; aquí se pasa el valor cifrado como token)
        const token = cred ?? 'demo-token';

        const upstream = new Request(`https://api.example.com${body.path ?? ''}`, {
          method: body.method ?? 'GET',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: body.body ? JSON.stringify(body.body) : undefined,
        });

        const resp = await fetch(upstream);
        const text = await resp.text();
        return new Response(text, { status: resp.status, headers: resp.headers });
      } catch (e) {
        return Response.json({ ok: false, error: String(e) }, { status: 500 });
      }
    }

    return new Response('not found', { status: 404 });
  }
}

// -----------------------------------------------------------------------------
// Worker central — enrutador stateless (edge ingress)
// -----------------------------------------------------------------------------
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const ai = createAI({ binding: env.AI, gateway: 'default' });

    // Health check
    if (url.pathname === '/health') {
      return Response.json({ ok: true, service: 'artefactools-platform', ts: Date.now() });
    }

    // /api/* → sesión de usuario (UserSessionDO por usuario autenticado)
    if (url.pathname.startsWith('/api/')) {
      const sessionId = env.USER_SESSION.idFromName('default-user');
      const stub = env.USER_SESSION.get(sessionId);
      return stub.fetch(request);
    }

    // /agents/* → artefactools (Durable Objects por herramienta)
    if (url.pathname.startsWith('/agents/')) {
      const seg = url.pathname.split('/').filter(Boolean); // ['agents', name, ...rest]
      const artefactoolName = seg[1] ?? 'default';
      const id = env.ARTEFACTOOL.idFromName(artefactoolName);
      const stub = env.ARTEFACTOOL.get(id);
      // Reescribir path para el DO
      const reqUrl = new URL(request.url);
      reqUrl.pathname = '/' + seg.slice(2).join('/') || '/';
      const proxied = new Request(reqUrl.toString(), request);
      return stub.fetch(proxied);
    }

    // /mcp/* → broker de protocolo MCP (CredentialVaultDO como router de credenciales)
    if (url.pathname.startsWith('/mcp/')) {
      const vaultId = env.VAULT.idFromName('default-vault');
      const stub = env.VAULT.get(vaultId);
      return stub.fetch(request);
    }

    // Fallback: servir assets estáticos (frontend)
    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;
