import { DurableObject } from 'cloudflare:workers';
import type { DurableObjectState } from 'cloudflare:workers';

// -----------------------------------------------------------------------------
// Tipos
// -----------------------------------------------------------------------------
interface Env {
  USER_SESSION: DurableObjectNamespace;
  ARTEFACTOOL: DurableObjectNamespace;
  VAULT: DurableObjectNamespace;
  AI: any;
  ASSETS: Fetcher;
  LOADER: WorkerLoader;
}

interface MessageRow {
  id: number;
  role: string;
  content: string;
  created_at: number;
}

// -----------------------------------------------------------------------------
// Utilidad criptográfica (Web Crypto API) — usada por CredentialVaultDO
// -----------------------------------------------------------------------------
const CRYPTO_ALGO = 'AES-GCM';

async function deriveKey(material: CryptoKey | BufferSource, salt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey(
    'raw',
    material,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
    base,
    { name: CRYPTO_ALGO, length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptValue(plaintext: string, secret: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(new TextEncoder().encode(secret), salt);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: CRYPTO_ALGO, iv }, key, new TextEncoder().encode(plaintext));
  const combined = new Uint8Array(salt.length + iv.length + ct.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(ct), salt.length + iv.length);
  return btoa(String.fromCharCode(...combined));
}

export async function decryptValue(ciphertextB64: string, secret: string): Promise<string> {
  const combined = new Uint8Array(atob(ciphertextB64).split('').map((c) => c.charCodeAt(0)));
  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const ct = combined.slice(28);
  const key = await deriveKey(new TextEncoder().encode(secret), salt);
  const pt = await crypto.subtle.decrypt({ name: CRYPTO_ALGO, iv }, key, ct);
  return new TextDecoder().decode(pt);
}

const VAULT_SECRET = 'artefactools-vault-secret-change-in-production';

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
        const v = row.value as { id: number; role: string; content: string; created_at: number };
        messages.push({ id: v.id, role: v.role, content: v.content, created_at: v.created_at });
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
          body.role, body.content, Date.now()
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
        const v = row.value as { instance_id: string; name: string; created_at: number };
        items.push({ instance_id: v.instance_id, name: v.name, created_at: v.created_at });
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
          id.toString(), body.name, Date.now()
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
      'initialized', 'true', String(Date.now())
    );
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS mcp_tools (
        name TEXT PRIMARY KEY,
        description TEXT NOT NULL,
        input_schema TEXT NOT NULL
      );
    `);
    this.ctx.storage.sql.exec(
      "INSERT OR REPLACE INTO mcp_tools (name, description, input_schema) VALUES (?, ?, ?)",
      'get_state', 'Devuelve el estado actual de la artefactool', '{"type":"object","properties":{}}'
    );
    this.ctx.storage.sql.exec(
      "INSERT OR REPLACE INTO mcp_tools (name, description, input_schema) VALUES (?, ?, ?)",
      'set_state', 'Establece una clave/valor en el estado de la artefactool', '{"type":"object","properties":{"key":{"type":"string"},"value":{"type":"string"}}}'
    );
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // --- MCP (Model Context Protocol) ---
    if (url.pathname === '/mcp' && request.method === 'POST') {
      try {
        const body = (await request.json()) as {
          jsonrpc?: string;
          method?: string;
          params?: any;
          id?: any;
        };
        if (body.method === 'initialize') {
          return Response.json({
            jsonrpc: '2.0',
            id: body.id,
            result: {
              protocolVersion: '2024-11-05',
              capabilities: { tools: {} },
              serverInfo: { name: 'artefactool-' + (url.searchParams.get('name') ?? 'default'), version: '0.1.0' },
            },
          });
        }
        if (body.method === 'tools/list') {
          const cursor = this.ctx.storage.sql.exec('SELECT name, description, input_schema FROM mcp_tools');
          const tools: any[] = [];
          for (const row of cursor) {
            const v = row.value as { name: string; description: string; input_schema: string } | null;
            if (!v) continue;
            tools.push({ name: v.name, description: v.description, inputSchema: JSON.parse(v.input_schema) });
          }
          return Response.json({ jsonrpc: '2.0', id: body.id, result: { tools } });
        }
        if (body.method === 'tools/call') {
          const name = body.params?.name;
          const args = body.params?.arguments ?? {};
          if (name === 'get_state') {
            const cursor = this.ctx.storage.sql.exec('SELECT key, value FROM state');
            const state: Record<string, string> = {};
            for (const row of cursor) {
              const v = row.value as unknown as [string, string];
              state[v[0]] = v[1];
            }
            return Response.json({ jsonrpc: '2.0', id: body.id, result: { content: [{ type: 'text', text: JSON.stringify(state, null, 2) }] } });
          }
          if (name === 'set_state') {
            this.ctx.storage.sql.exec(
              'INSERT OR REPLACE INTO state (key, value, updated_at) VALUES (?, ?, ?)',
              args.key, String(args.value), String(Date.now())
            );
            return Response.json({ jsonrpc: '2.0', id: body.id, result: { content: [{ type: 'text', text: `Estado ${args.key} = ${args.value} guardado` }] } });
          }
          return Response.json({
            jsonrpc: '2.0',
            id: body.id,
            error: { code: -32601, message: 'Method not found' },
          });
        }
        return Response.json({
          jsonrpc: '2.0',
          id: body.id,
          error: { code: -32600, message: 'Invalid Request' },
        });
      } catch (e) {
        return Response.json({ ok: false, error: String(e) }, { status: 500 });
      }
    }

    if (url.pathname === '/v1/state' && request.method === 'GET') {
      const cursor = this.ctx.storage.sql.exec('SELECT key, value, updated_at FROM state');
      const items: Record<string, string> = {};
      for (const row of cursor) {
        const v = row.value as { key: string; value: string };
        items[v.key] = v.value;
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
          body.key, String(body.value), String(Date.now())
        );
        return Response.json({ ok: true });
      } catch {
        return Response.json({ ok: false, error: 'invalid json' }, { status: 400 });
      }
    }

    // --- Ejecución aislada de código ligero (Dynamic Workers / WorkerLoader) ---
    if (url.pathname === '/v1/execute' && request.method === 'POST') {
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

    // --- Virtualizador de repositorios GitHub ---
    if (url.pathname === '/v1/virtualize' && request.method === 'POST') {
      try {
        const body = (await request.json()) as { repo_url?: string };
        if (!body.repo_url) {
          return Response.json({ ok: false, error: 'repo_url required' }, { status: 400 });
        }
        const match = body.repo_url.match(/github\.com[:/]([^\/]+)\/([^\/]+?)(?:\.git)?$/);
        if (!match) {
          return Response.json({ ok: false, error: 'URL de GitHub inválida' }, { status: 400 });
        }
        const owner = match[1];
        const repo = match[2];
        this.ctx.storage.sql.exec(
          'INSERT OR REPLACE INTO state (key, value, updated_at) VALUES (?, ?, ?)',
          'virtualized_repo', `${owner}/${repo}`, String(Date.now())
        );
        this.ctx.storage.sql.exec(
          'INSERT OR REPLACE INTO state (key, value, updated_at) VALUES (?, ?, ?)',
          'virtualized_status', 'clonado', String(Date.now())
        );
        return Response.json({
          ok: true,
          repo: `${owner}/${repo}`,
          status: 'clonado',
          message: `Repositorio ${owner}/${repo} virtualizado en este Durable Object`,
        });
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

    // Listar servicios configurados (sin valores)
    if (url.pathname.startsWith('/v1/vault/credentials') && request.method === 'GET') {
      const cursor = this.ctx.storage.sql.exec('SELECT service, updated_at FROM credentials');
      const services: { service: string; updated_at: number }[] = [];
      for (const row of cursor) {
        const v = row.value as { service: string; updated_at: number };
        services.push({ service: v.service, updated_at: v.updated_at });
      }
      return Response.json({ ok: true, services });
    }

    // Almacenar una credencial (cifrada en repos)
    if (url.pathname === '/v1/vault/credentials' && request.method === 'POST') {
      try {
        const body = (await request.json()) as { service?: string; value?: string };
        if (!body.service || !body.value) {
          return Response.json({ ok: false, error: 'service and value required' }, { status: 400 });
        }
        const encrypted = await encryptValue(body.value, VAULT_SECRET);
        this.ctx.storage.sql.exec(
          'INSERT OR REPLACE INTO credentials (service, encrypted_value, updated_at) VALUES (?, ?, ?)',
          body.service, encrypted, String(Date.now())
        );
        return Response.json({ ok: true, service: body.service });
      } catch (e) {
        return Response.json({ ok: false, error: String(e) }, { status: 500 });
      }
    }

    // Ejecutar acción externa inyectando credencial (zero-leak: el LLM nunca ve el token)
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
          body.service
        );
        let encrypted: string | null = null;
        for (const row of cursor) {
          const v = row.value as { encrypted_value: string } | null;
          if (v) encrypted = v.encrypted_value;
        }

        const requiresApproval = body.requires_approval ?? false;

        // Si requiere aprobación y no hay credencial almacenada, crear solicitud pendiente
        if (requiresApproval && encrypted === null) {
          this.ctx.storage.sql.exec(
            'INSERT INTO approvals (service, action, payload, status, created_at) VALUES (?, ?, ?, ?, ?)',
            body.service, body.method ?? 'POST', JSON.stringify(body.body ?? {}), 'pending', String(Date.now())
          );
          const idCursor = this.ctx.storage.sql.exec('SELECT last_insert_rowid() AS id');
          let approvalId = '0';
          for (const row of idCursor) {
            const v = row.value as { id: number };
            approvalId = String(v.id);
          }
          return Response.json(
            { ok: false, approval_required: true, approval_id: approvalId, message: 'Aprobación humana requerida antes de ejecutar' },
            { status: 403 }
          );
        }

        // Resolver credencial (desencriptar internamente; nunca sale del DO)
        const token = encrypted ? await decryptValue(encrypted, VAULT_SECRET) : 'demo-token';

        // Si requiere aprobación y hay credencial, crear solicitud de aprobación antes de ejecutar
        if (requiresApproval && encrypted) {
          this.ctx.storage.sql.exec(
            'INSERT INTO approvals (service, action, payload, status, created_at) VALUES (?, ?, ?, ?, ?)',
            body.service, body.method ?? 'POST', JSON.stringify(body.body ?? {}), 'pending', String(Date.now())
          );
          const idCursor = this.ctx.storage.sql.exec('SELECT last_insert_rowid() AS id');
          let approvalId = '0';
          for (const row of idCursor) {
            const v = row.value as { id: number };
            approvalId = String(v.id);
          }
          return Response.json(
            { ok: false, approval_required: true, approval_id: approvalId, message: 'Acción crítica: esperando aprobación humana' },
            { status: 403 }
          );
        }

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

    // Aprobar o rechazar una solicitud pendiente (human-in-the-loop)
    if (url.pathname === '/v1/vault/approvals' && request.method === 'POST') {
      try {
        const body = (await request.json()) as { approval_id?: string; action?: 'approve' | 'reject' };
        if (!body.approval_id || !body.action) {
          return Response.json({ ok: false, error: 'approval_id and action required' }, { status: 400 });
        }
        this.ctx.storage.sql.exec(
          'UPDATE approvals SET status = ? WHERE id = ?',
          body.action, Number(body.approval_id)
        );
        return Response.json({ ok: true, approval_id: body.approval_id, status: body.action });
      } catch {
        return Response.json({ ok: false, error: 'invalid json' }, { status: 400 });
      }
    }

    // Listar aprobaciones pendientes
    if (url.pathname === '/v1/vault/approvals' && request.method === 'GET') {
      const cursor = this.ctx.storage.sql.exec(
        'SELECT id, service, action, payload, status, created_at FROM approvals WHERE status = ? ORDER BY created_at DESC',
        'pending'
      );
      const items: any[] = [];
      for (const row of cursor) {
        const v = row.value as { id: number; service: string; action: string; payload: string; status: string; created_at: number };
        items.push({ id: v.id, service: v.service, action: v.action, payload: v.payload, status: v.status, created_at: v.created_at });
      }
      return Response.json({ ok: true, items });
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

    // Health check
    if (url.pathname === '/health') {
      return Response.json({ ok: true, service: 'artefactools-platform', ts: Date.now() });
    }

    // /api/* → sesión de usuario (UserSessionDO por usuario autenticado)
    if (url.pathname.startsWith('/api/')) {
      const sessionId = env.USER_SESSION.idFromName('default-user');
      const stub = env.USER_SESSION.get(sessionId);
      const reqUrl = new URL(request.url);
      reqUrl.pathname = '/v1' + reqUrl.pathname.slice('/api'.length);
      const body = request.method === 'GET' || request.method === 'HEAD' ? undefined : await request.text();
      const proxied = new Request(reqUrl.toString(), {
        method: request.method,
        headers: request.headers,
        body: body !== undefined ? body : undefined,
      });
      return stub.fetch(proxied);
    }

    // /agents/* → artefactools (Durable Objects por herramienta)
    if (url.pathname.startsWith('/agents/')) {
      const seg = url.pathname.split('/').filter(Boolean);
      const artefactoolName = seg[1] ?? 'default';
      const id = env.ARTEFACTOOL.idFromName(artefactoolName);
      const stub = env.ARTEFACTOOL.get(id);
      const reqUrl = new URL(request.url);
      reqUrl.pathname = '/' + seg.slice(2).join('/') || '/';
      const body = request.method === 'GET' || request.method === 'HEAD' ? undefined : await request.text();
      const proxied = new Request(reqUrl.toString(), {
        method: request.method,
        headers: request.headers,
        body: body !== undefined ? body : undefined,
      });
      return stub.fetch(proxied);
    }

    // /mcp/* → protocolo MCP de artefactools específicas
    if (url.pathname.startsWith('/mcp/')) {
      const seg = url.pathname.split('/').filter(Boolean);
      const artefactoolName = seg[1] ?? 'default';
      const stub = env.ARTEFACTOOL.get(artefactoolName);
      const body = request.method === 'GET' || request.method === 'HEAD' ? undefined : await request.text();
      const proxied = new Request(request.url, {
        method: request.method,
        headers: request.headers,
        body: body !== undefined ? body : undefined,
      });
      return stub.fetch(proxied);
    }

    // /vault/* → bóveda de credenciales
    if (url.pathname.startsWith('/vault/')) {
      const vaultId = env.VAULT.idFromName('default-vault');
      const stub = env.VAULT.get(vaultId);
      const reqUrl = new URL(request.url);
      reqUrl.pathname = '/v1' + reqUrl.pathname;
      const body = request.method === 'GET' || request.method === 'HEAD' ? undefined : await request.text();
      const proxied = new Request(reqUrl.toString(), {
        method: request.method,
        headers: request.headers,
        body: body !== undefined ? body : undefined,
      });
      return stub.fetch(proxied);
    }

    // Fallback: servir assets estáticos (frontend)
    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;
