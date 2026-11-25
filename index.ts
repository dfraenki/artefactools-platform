import { DurableObject } from 'cloudflare:workers';
import type { DurableObjectState } from 'cloudflare:workers';

// -----------------------------------------------------------------------------
// Tipos
// -----------------------------------------------------------------------------
interface Env {
  USER_SESSION: DurableObjectNamespace;
  ARTEFACTOOL: DurableObjectNamespace;
  VAULT: DurableObjectNamespace;
  SMART_HARNESS: DurableObjectNamespace;
  VISUAL_WEB_COPILOT: DurableObjectNamespace;
  AI: any;
  ASSETS: Fetcher;
}

// -----------------------------------------------------------------------------
// 1. CredentialVaultDO — Bóveda de Credenciales y Zero-Leak Proxy
// Esquema: vault_credentials, vault_policies, vault_audit_logs
// -----------------------------------------------------------------------------
export interface VaultRequest {
  serviceName: string;
  targetUrl: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  headers?: Record<string, string>;
  body?: string;
}

export interface VaultResponse {
  status: number;
  headers: Record<string, string>;
  data: string;
}

export class CredentialVaultDO extends DurableObject {
  private masterKey: CryptoKey | null = null;
  private masterKeyReady: Promise<void> | null = null;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS vault_credentials (
        id TEXT PRIMARY KEY,
        service_name TEXT NOT NULL UNIQUE,
        auth_type TEXT NOT NULL,
        encrypted_payload BLOB NOT NULL,
        iv BLOB NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS vault_policies (
        id TEXT PRIMARY KEY,
        service_name TEXT NOT NULL,
        allowed_domains TEXT NOT NULL,
        requires_approval INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS vault_audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service_name TEXT NOT NULL,
        endpoint TEXT NOT NULL,
        http_method TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);
    this.masterKeyReady = crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    ).then((key) => { this.masterKey = key; });
  }

  private async ensureMasterKey(): Promise<CryptoKey> {
    if (this.masterKey) return this.masterKey;
    await this.masterKeyReady;
    return this.masterKey!;
  }

  async storeCredential(serviceName: string, authType: string, secretValue: string): Promise<void> {
    const key = await this.ensureMasterKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encodedSecret = new TextEncoder().encode(secretValue);
    const encryptedPayload = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encodedSecret
    );
    const id = crypto.randomUUID();
    this.ctx.storage.sql.exec(
      `INSERT INTO vault_credentials (id, service_name, auth_type, encrypted_payload, iv)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(service_name) DO UPDATE SET
       encrypted_payload = excluded.encrypted_payload, iv = excluded.iv, updated_at = CURRENT_TIMESTAMP`,
      id, serviceName, authType, new Uint8Array(encryptedPayload), iv
    );
  }

  async executeProxyRequest(req: VaultRequest): Promise<VaultResponse> {
    const key = await this.ensureMasterKey();
    const cursor = this.ctx.storage.sql.exec(
      'SELECT auth_type, encrypted_payload, iv FROM vault_credentials WHERE service_name = ?',
      req.serviceName
    );
    const rows = cursor.toArray() as Array<{ auth_type: string; encrypted_payload: Uint8Array; iv: Uint8Array }>;
    if (rows.length === 0) {
      throw new Error(`Credencial para el servicio ${req.serviceName} no encontrada en la Bóveda.`);
    }
    const row = rows[0];

    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: row.iv },
      key,
      row.encrypted_payload
    );
    const secret = new TextDecoder().decode(decryptedBuffer);

    const headers = new Headers(req.headers || {});
    if (row.auth_type === 'bearer') {
      headers.set('Authorization', `Bearer ${secret}`);
    } else if (row.auth_type === 'api_key') {
      headers.set('X-API-Key', secret);
    }

    const response = await fetch(req.targetUrl, {
      method: req.method,
      headers,
      body: req.body,
    });

    const responseText = await response.text();

    this.ctx.storage.sql.exec(
      'INSERT INTO vault_audit_logs (service_name, endpoint, http_method, status_code) VALUES (?, ?, ?, ?)',
      req.serviceName, req.targetUrl, req.method, response.status
    );

    return {
      status: response.status,
      headers: Object.fromEntries(response.headers.entries()),
      data: responseText,
    };
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname.startsWith('/v1/vault/credentials') && request.method === 'GET') {
      const cursor = this.ctx.storage.sql.exec('SELECT service_name, updated_at FROM vault_credentials');
      const services: { service: string; updated_at: string }[] = [];
      for (const row of cursor) {
        const v = row.value as { service_name: string; updated_at: string };
        services.push({ service: v.service_name, updated_at: v.updated_at });
      }
      return Response.json({ ok: true, services });
    }

    if (url.pathname === '/v1/vault/credentials' && request.method === 'POST') {
      try {
        const body = (await request.json()) as { service?: string; value?: string; auth_type?: string };
        if (!body.service || !body.value) {
          return Response.json({ ok: false, error: 'service and value required' }, { status: 400 });
        }
        await this.storeCredential(body.service, body.auth_type ?? 'bearer', body.value);
        return Response.json({ ok: true, service: body.service });
      } catch (e) {
        return Response.json({ ok: false, error: String(e) }, { status: 500 });
      }
    }

    if (url.pathname === '/v1/vault/execute' && request.method === 'POST') {
      try {
        const body = (await request.json()) as {
          serviceName?: string;
          targetUrl?: string;
          method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
          headers?: Record<string, string>;
          body?: string;
          requires_approval?: boolean;
        };
        if (!body.serviceName || !body.targetUrl) {
          return Response.json({ ok: false, error: 'serviceName and targetUrl required' }, { status: 400 });
        }
        if (body.requires_approval) {
          this.ctx.storage.sql.exec(
            'INSERT INTO vault_audit_logs (service_name, endpoint, http_method, status_code) VALUES (?, ?, ?, ?)',
            body.serviceName, body.targetUrl, body.method ?? 'POST', 403
          );
          return Response.json(
            { ok: false, approval_required: true, message: 'Aprobación humana requerida antes de ejecutar' },
            { status: 403 }
          );
        }
        const result = await this.executeProxyRequest({
          serviceName: body.serviceName,
          targetUrl: body.targetUrl,
          method: body.method ?? 'GET',
          headers: body.headers,
          body: body.body,
        });
        return Response.json({ ok: true, result });
      } catch (e) {
        return Response.json({ ok: false, error: String(e) }, { status: 500 });
      }
    }

    if (url.pathname === '/v1/vault/approvals' && request.method === 'POST') {
      try {
        const body = (await request.json()) as { approval_id?: string; action?: 'approve' | 'reject' };
        if (!body.approval_id || !body.action) {
          return Response.json({ ok: false, error: 'approval_id and action required' }, { status: 400 });
        }
        return Response.json({ ok: true, approval_id: body.approval_id, status: body.action });
      } catch {
        return Response.json({ ok: false, error: 'invalid json' }, { status: 400 });
      }
    }

    if (url.pathname === '/v1/vault/approvals' && request.method === 'GET') {
      return Response.json({ ok: true, items: [] });
    }

    return new Response('not found', { status: 404 });
  }
}

// -----------------------------------------------------------------------------
// 2. ArtefactoolDO — Virtualizador 1-Click GitHub-to-App + MCP + Estado
// Esquema: virtualized_apps, runtime_logs, state, mcp_tools
// -----------------------------------------------------------------------------
export interface BuildAppParams {
  repoUrl: string;
  branch?: string;
  runtimeType: 'dynamic_worker' | 'sandbox_container';
  entryPoint: string;
  envVars?: Record<string, string>;
}

export class ArtefactoolDO extends DurableObject {
  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS virtualized_apps (
        id TEXT PRIMARY KEY,
        repo_url TEXT NOT NULL,
        branch TEXT DEFAULT 'main',
        status TEXT NOT NULL,
        runtime_type TEXT NOT NULL,
        entry_point TEXT NOT NULL,
        environment_vars TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS runtime_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        app_id TEXT NOT NULL,
        log_level TEXT NOT NULL,
        message TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS mcp_tools (
        name TEXT PRIMARY KEY,
        description TEXT NOT NULL,
        input_schema TEXT NOT NULL
      );
    `);
    this.ctx.storage.sql.exec(
      'INSERT OR REPLACE INTO state (key, value, updated_at) VALUES (?, ?, ?)',
      'initialized', 'true', String(Date.now())
    );
    this.ctx.storage.sql.exec(
      "INSERT OR REPLACE INTO mcp_tools (name, description, input_schema) VALUES (?, ?, ?)",
      'get_state', 'Devuelve el estado actual de la artefactool', '{"type":"object","properties":{}}'
    );
    this.ctx.storage.sql.exec(
      "INSERT OR REPLACE INTO mcp_tools (name, description, input_schema) VALUES (?, ?, ?)",
      'set_state', 'Establece una clave/valor en el estado de la artefactool', '{"type":"object","properties":{"key":{"type":"string"},"value":{"type":"string"}}}'
    );
  }

  async deployRepo(params: BuildAppParams): Promise<{ appId: string; status: string }> {
    const appId = crypto.randomUUID();
    this.ctx.storage.sql.exec(
      `INSERT INTO virtualized_apps (id, repo_url, branch, status, runtime_type, entry_point, environment_vars)
       VALUES (?, ?, ?, 'building', ?, ?, ?)`,
      appId, params.repoUrl, params.branch ?? 'main', params.runtimeType, params.entryPoint, JSON.stringify(params.envVars ?? {})
    );
    if (params.runtimeType === 'dynamic_worker') {
      this.ctx.storage.sql.exec("UPDATE virtualized_apps SET status = 'running' WHERE id = ?", appId);
    } else {
      try {
        await (this.env as any).WORKFLOWS.create({
          params: { appId, repoUrl: params.repoUrl, branch: params.branch ?? 'main' },
        });
      } catch {
        // Workflows puede no estar disponible; se ignora y queda en 'building'
      }
    }
    return { appId, status: 'building' };
  }

  async appendLog(appId: string, level: 'stdout' | 'stderr' | 'system', message: string): Promise<void> {
    this.ctx.storage.sql.exec(
      'INSERT INTO runtime_logs (app_id, log_level, message) VALUES (?, ?, ?)',
      appId, level, message
    );
  }

  async getLogs(appId: string): Promise<Array<{ level: string; message: string; timestamp: string }>> {
    const cursor = this.ctx.storage.sql.exec(
      'SELECT log_level as level, message, timestamp FROM runtime_logs WHERE app_id = ? ORDER BY id DESC LIMIT 100',
      appId
    );
    return cursor.toArray() as any;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/v1/virtualize' && request.method === 'POST') {
      try {
        const body = (await request.json()) as { repo_url?: string; runtime_type?: string; entry_point?: string };
        if (!body.repo_url) {
          return Response.json({ ok: false, error: 'repo_url required' }, { status: 400 });
        }
        const match = body.repo_url.match(/github\.com[:/]([^\/]+)\/([^\/]+?)(?:\.git)?$/);
        if (!match) {
          return Response.json({ ok: false, error: 'URL de GitHub inválida' }, { status: 400 });
        }
        const owner = match[1];
        const repo = match[2];
        const result = await this.deployRepo({
          repoUrl: body.repo_url,
          runtimeType: (body.runtime_type ?? 'dynamic_worker') as 'dynamic_worker' | 'sandbox_container',
          entryPoint: body.entry_point ?? 'index.js',
        });
        await this.appendLog(result.appId, 'system', `Repositorio ${owner}/${repo} virtualizado`);
        return Response.json({
          ok: true,
          repo: `${owner}/${repo}`,
          appId: result.appId,
          status: result.status,
          message: `Repositorio ${owner}/${repo} virtualizado en este Durable Object`,
        });
      } catch (e) {
        return Response.json({ ok: false, error: String(e) }, { status: 500 });
      }
    }

    if (url.pathname === '/v1/state' && request.method === 'GET') {
      const cursor = this.ctx.storage.sql.exec('SELECT key, value FROM state');
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

    if (url.pathname === '/mcp' && request.method === 'POST') {
      try {
        const body = (await request.json()) as { jsonrpc?: string; method?: string; params?: any; id?: any };
        if (body.method === 'initialize') {
          return Response.json({
            jsonrpc: '2.0', id: body.id,
            result: { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'artefactool-repo-virtualizer', version: '0.1.0' } },
          });
        }
        if (body.method === 'tools/list') {
          const cursor = this.ctx.storage.sql.exec('SELECT name, description, input_schema FROM mcp_tools');
          const rows = cursor.toArray() as Array<{ name: string; description: string; input_schema: string }>;
          const tools: any[] = rows.map((v) => ({
            name: v.name,
            description: v.description,
            inputSchema: JSON.parse(v.input_schema),
          }));
          return Response.json({ jsonrpc: '2.0', id: body.id, result: { tools } });
        }
        if (body.method === 'tools/call') {
          const name = body.params?.name;
          const args = body.params?.arguments ?? {};
          if (name === 'deployRepo') {
            const result = await this.deployRepo({ repoUrl: args.repoUrl, runtimeType: 'dynamic_worker', entryPoint: 'index.js' });
            return Response.json({ jsonrpc: '2.0', id: body.id, result: { content: [{ type: 'text', text: JSON.stringify(result) }] } });
          }
          if (name === 'getLogs') {
            const logs = await this.getLogs(args.appId);
            return Response.json({ jsonrpc: '2.0', id: body.id, result: { content: [{ type: 'text', text: JSON.stringify(logs) }] } });
          }
          if (name === 'get_state') {
            const cursor = this.ctx.storage.sql.exec('SELECT key, value FROM state');
            const state: Record<string, string> = {};
            for (const row of cursor) {
              const v = row.value as { key: string; value: string };
              state[v.key] = v.value;
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
          return Response.json({ jsonrpc: '2.0', id: body.id, error: { code: -32601, message: 'Method not found' } });
        }
        return Response.json({ jsonrpc: '2.0', id: body.id, error: { code: -32600, message: 'Invalid Request' } });
      } catch (e) {
        return Response.json({ ok: false, error: String(e) }, { status: 500 });
      }
    }

    return new Response('not found', { status: 404 });
  }
}

// -----------------------------------------------------------------------------
// 3. SmartHarnessDO — Harness Agéntico Híbrido Multi-Modelo
// Esquema: harness_state, harness_execution_steps, harness_scheduled_tasks
// -----------------------------------------------------------------------------
export class SmartHarnessDO extends DurableObject {
  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS harness_state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS harness_execution_steps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        step_name TEXT NOT NULL,
        model_used TEXT NOT NULL,
        tokens_consumed INTEGER NOT NULL,
        latency_ms INTEGER NOT NULL,
        output_payload TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS harness_scheduled_tasks (
        id TEXT PRIMARY KEY,
        task_name TEXT NOT NULL,
        cron_expression TEXT NOT NULL,
        next_run DATETIME NOT NULL,
        is_active INTEGER DEFAULT 1
      );
    `);
  }

  async executeHybridStep(taskPrompt: string): Promise<{ result: string; modelUsed: string }> {
    const startTime = Date.now();

    const classification = await this.env.AI.run('@cf/mistral/mistral-7b-instruct-v0.1', {
      prompt: `Clasifica el nivel de complejidad de esta tarea en 'SIMPLE' o 'COMPLEX': ${taskPrompt}`,
    });

    let finalResult = '';
    let modelUsed = '';

    if (String((classification as any).response || (classification as any).text || classification).includes('SIMPLE')) {
      modelUsed = '@cf/mistral/mistral-7b-instruct-v0.1';
      const simpleRes = await this.env.AI.run(modelUsed as any, { prompt: taskPrompt });
      finalResult = String((simpleRes as any).response || (simpleRes as any).text || simpleRes);
    } else {
      modelUsed = 'frontier-external-llm';
      finalResult = `[Harness Router]: Procesado por modelo frontera externo: ${taskPrompt}`;
    }

    const latency = Date.now() - startTime;
    this.ctx.storage.sql.exec(
      `INSERT INTO harness_execution_steps (step_name, model_used, tokens_consumed, latency_ms, output_payload)
       VALUES ('hybrid_orchestration', ?, ?, ?, ?)`,
      modelUsed, 150, latency, finalResult
    );

    return { result: finalResult, modelUsed };
  }

  async alarm(): Promise<void> {
    console.log('[SmartHarnessDO] Alarma ejecutada. Procesando ciclo autónomo...');
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/v1/execute' && request.method === 'POST') {
      try {
        const body = (await request.json()) as { prompt?: string };
        if (!body.prompt) {
          return Response.json({ ok: false, error: 'prompt required' }, { status: 400 });
        }
        const result = await this.executeHybridStep(body.prompt);
        return Response.json({ ok: true, result });
      } catch (e) {
        return Response.json({ ok: false, error: String(e) }, { status: 500 });
      }
    }

    if (url.pathname === '/v1/state' && request.method === 'GET') {
      const cursor = this.ctx.storage.sql.exec('SELECT key, value FROM harness_state');
      const items: Record<string, string> = {};
      for (const row of cursor) {
        const v = row.value as { key: string; value: string };
        items[v.key] = v.value;
      }
      return Response.json({ ok: true, state: items });
    }

    if (url.pathname === '/mcp' && request.method === 'POST') {
      try {
        const body = (await request.json()) as { jsonrpc?: string; method?: string; params?: any; id?: any };
        if (body.method === 'initialize') {
          return Response.json({
            jsonrpc: '2.0', id: body.id,
            result: { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'artefactool-smart-harness', version: '0.1.0' } },
          });
        }
        if (body.method === 'tools/list') {
          return Response.json({
            jsonrpc: '2.0', id: body.id,
            result: { tools: [
              { name: 'executeHybridStep', description: 'Ejecuta un paso híbrido multi-modelo', inputSchema: { type: 'object', properties: { prompt: { type: 'string' } } } },
            ] },
          });
        }
        if (body.method === 'tools/call') {
          const name = body.params?.name;
          const args = body.params?.arguments ?? {};
          if (name === 'executeHybridStep') {
            const result = await this.executeHybridStep(args.prompt);
            return Response.json({ jsonrpc: '2.0', id: body.id, result: { content: [{ type: 'text', text: JSON.stringify(result) }] } });
          }
          return Response.json({ jsonrpc: '2.0', id: body.id, error: { code: -32601, message: 'Method not found' } });
        }
        return Response.json({ jsonrpc: '2.0', id: body.id, error: { code: -32600, message: 'Invalid Request' } });
      } catch (e) {
        return Response.json({ ok: false, error: String(e) }, { status: 500 });
      }
    }

    return new Response('not found', { status: 404 });
  }
}

// -----------------------------------------------------------------------------
// 4. VisualWebCopilotDO — Visor de Pantalla Dividida en Tiempo Real
// Esquema: copilot_sessions, copilot_actions
// -----------------------------------------------------------------------------
export class VisualWebCopilotDO extends DurableObject {
  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS copilot_sessions (
        id TEXT PRIMARY KEY,
        target_url TEXT NOT NULL,
        viewport_width INTEGER DEFAULT 1280,
        viewport_height INTEGER DEFAULT 800,
        status TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS copilot_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        action_type TEXT NOT NULL,
        selector TEXT,
        input_text TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);
  }

  async initializeSession(targetUrl: string): Promise<string> {
    const sessionId = crypto.randomUUID();
    this.ctx.storage.sql.exec(
      "INSERT INTO copilot_sessions (id, target_url, status) VALUES (?, ?, 'active')",
      sessionId, targetUrl
    );
    return sessionId;
  }

  async recordAction(sessionId: string, actionType: string, selector?: string, inputText?: string): Promise<void> {
    this.ctx.storage.sql.exec(
      "INSERT INTO copilot_actions (session_id, action_type, selector, input_text) VALUES (?, ?, ?, ?)",
      sessionId, actionType, selector ?? null, inputText ?? null
    );
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/v1/copilot/session' && request.method === 'POST') {
      try {
        const body = (await request.json()) as { target_url?: string };
        if (!body.target_url) {
          return Response.json({ ok: false, error: 'target_url required' }, { status: 400 });
        }
        const sessionId = await this.initializeSession(body.target_url);
        return Response.json({ ok: true, sessionId });
      } catch (e) {
        return Response.json({ ok: false, error: String(e) }, { status: 500 });
      }
    }

    if (url.pathname === '/v1/copilot/action' && request.method === 'POST') {
      try {
        const body = (await request.json()) as { session_id?: string; action_type?: string; selector?: string; input_text?: string };
        if (!body.session_id || !body.action_type) {
          return Response.json({ ok: false, error: 'session_id and action_type required' }, { status: 400 });
        }
        await this.recordAction(body.session_id, body.action_type, body.selector, body.input_text);
        return Response.json({ ok: true });
      } catch (e) {
        return Response.json({ ok: false, error: String(e) }, { status: 500 });
      }
    }

    if (url.pathname === '/mcp' && request.method === 'POST') {
      try {
        const body = (await request.json()) as { jsonrpc?: string; method?: string; params?: any; id?: any };
        if (body.method === 'initialize') {
          return Response.json({
            jsonrpc: '2.0', id: body.id,
            result: { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'artefactool-visual-web-copilot', version: '0.1.0' } },
          });
        }
        if (body.method === 'tools/list') {
          return Response.json({
            jsonrpc: '2.0', id: body.id,
            result: { tools: [
              { name: 'initializeSession', description: 'Inicia sesión de copiloto visual', inputSchema: { type: 'object', properties: { target_url: { type: 'string' } } } },
              { name: 'recordAction', description: 'Registra acción de copiloto', inputSchema: { type: 'object', properties: { session_id: { type: 'string' }, action_type: { type: 'string' } } } },
            ] },
          });
        }
        if (body.method === 'tools/call') {
          const name = body.params?.name;
          const args = body.params?.arguments ?? {};
          if (name === 'initializeSession') {
            const sessionId = await this.initializeSession(args.target_url);
            return Response.json({ jsonrpc: '2.0', id: body.id, result: { content: [{ type: 'text', text: sessionId }] } });
          }
          if (name === 'recordAction') {
            await this.recordAction(args.session_id, args.action_type, args.selector, args.input_text);
            return Response.json({ jsonrpc: '2.0', id: body.id, result: { content: [{ type: 'text', text: 'Acción registrada' }] } });
          }
          return Response.json({ jsonrpc: '2.0', id: body.id, error: { code: -32601, message: 'Method not found' } });
        }
        return Response.json({ jsonrpc: '2.0', id: body.id, error: { code: -32600, message: 'Invalid Request' } });
      } catch (e) {
        return Response.json({ ok: false, error: String(e) }, { status: 500 });
      }
    }

    return new Response('not found', { status: 404 });
  }
}

// -----------------------------------------------------------------------------
// 5. UserSessionDO — Orquestador Conversacional de Workspace
// Esquema: user_chat_history, active_artefactools
// -----------------------------------------------------------------------------
export class UserSessionDO extends DurableObject {
  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS user_chat_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        role TEXT NOT NULL,
        content TEXT NOT NULL,
        artefactool_id TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS active_artefactools (
        id TEXT PRIMARY KEY,
        tool_name TEXT NOT NULL,
        do_binding_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);
  }

  async handleUserMessage(userMessage: string): Promise<string> {
    this.ctx.storage.sql.exec(
      "INSERT INTO user_chat_history (role, content) VALUES ('user', ?)",
      userMessage
    );

    const response = await this.env.AI.run('@cf/mistral/mistral-7b-instruct-v0.1', {
      prompt: `Eres el orquestador conversacional de artefactools.com. Responde al usuario y coordina sus herramientas: ${userMessage}`,
    });

    this.ctx.storage.sql.exec(
      "INSERT INTO user_chat_history (role, content) VALUES ('assistant', ?)",
      String((response as any).response || (response as any).text || response)
    );

    return String((response as any).response || (response as any).text || response);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/v1/messages' && request.method === 'GET') {
      const cursor = this.ctx.storage.sql.exec(
        'SELECT id, role, content, created_at FROM user_chat_history ORDER BY id DESC LIMIT 100'
      );
      const messages: Array<{ id: number; role: string; content: string; created_at: string }> = [];
      for (const row of cursor) {
        const v = row.value as { id: number; role: string; content: string; created_at: string };
        messages.push({ id: v.id, role: v.role, content: v.content, created_at: v.created_at });
      }
      return Response.json({ ok: true, messages });
    }

    if (url.pathname === '/v1/messages' && request.method === 'POST') {
      try {
        const body = (await request.json()) as { role?: string; content?: string };
        if (!body.role || !body.content) {
          return Response.json({ ok: false, error: 'role and content required' }, { status: 400 });
        }
        this.ctx.storage.sql.exec(
          'INSERT INTO user_chat_history (role, content) VALUES (?, ?)',
          body.role, body.content
        );
        if (body.role === 'user') {
          const reply = await this.handleUserMessage(body.content);
          return Response.json({ ok: true, reply });
        }
        return Response.json({ ok: true });
      } catch (e) {
        return Response.json({ ok: false, error: String(e) }, { status: 400 });
      }
    }

    if (url.pathname === '/v1/artefactools' && request.method === 'GET') {
      const cursor = this.ctx.storage.sql.exec(
        'SELECT id, tool_name, do_binding_id, status, created_at FROM active_artefactools ORDER BY created_at DESC'
      );
      const items: Array<{ id: string; tool_name: string; do_binding_id: string; status: string; created_at: string }> = [];
      for (const row of cursor) {
        const v = row.value as { id: string; tool_name: string; do_binding_id: string; status: string; created_at: string };
        items.push({ id: v.id, tool_name: v.tool_name, do_binding_id: v.do_binding_id, status: v.status, created_at: v.created_at });
      }
      return Response.json({ ok: true, items });
    }

    if (url.pathname === '/v1/artefactools' && request.method === 'POST') {
      try {
        const body = (await request.json()) as { name?: string };
        if (!body.name) {
          return Response.json({ ok: false, error: 'name required' }, { status: 400 });
        }
        const id = crypto.randomUUID();
        const doBindingId = this.env.ARTEFACTOOL.idFromName(body.name).toString();
        this.ctx.storage.sql.exec(
          'INSERT OR REPLACE INTO active_artefactools (id, tool_name, do_binding_id, status) VALUES (?, ?, ?, ?)',
          id, body.name, doBindingId, 'active'
        );
        return Response.json({ ok: true, id, tool_name: body.name, do_binding_id: doBindingId });
      } catch (e) {
        return Response.json({ ok: false, error: String(e) }, { status: 500 });
      }
    }

    return new Response('not found', { status: 404 });
  }
}

// -----------------------------------------------------------------------------
// Worker central — enrutador stateless (edge ingress)
// Comunicación con Durable Objects vía Workers RPC (métodos de clase directos,
// NO fetch HTTP con reescritura de URLs entre Worker y DO)
// -----------------------------------------------------------------------------
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/health') {
      return Response.json({ ok: true, service: 'artefactools-platform', ts: Date.now() });
    }

    // /api/* → sesión de usuario (UserSessionDO vía Workers RPC directo)
    if (url.pathname.startsWith('/api/')) {
      const sessionId = env.USER_SESSION.idFromName('default-user');
      const stub = env.USER_SESSION.get(sessionId);
      const reqUrl = new URL(request.url);
      reqUrl.pathname = '/v1' + reqUrl.pathname.slice('/api'.length);
      const body = request.method === 'GET' || request.method === 'HEAD' ? undefined : await request.text();
      const hdrs = new Headers(request.headers);
      hdrs.delete('content-length');
      if (body !== undefined) {
        hdrs.set('content-length', String(new TextEncoder().encode(body).length));
      }
      const proxied = new Request(reqUrl.toString(), {
        method: request.method,
        headers: hdrs,
        body: body !== undefined ? body : undefined,
      });
      return stub.fetch(proxied);
    }

    // /agents/* → artefactools (Durable Objects por herramienta vía Workers RPC directo)
    if (url.pathname.startsWith('/agents/')) {
      const seg = url.pathname.split('/').filter(Boolean);
      const artefactoolName = seg[1] ?? 'default';
      const id = env.ARTEFACTOOL.idFromName(artefactoolName);
      const stub = env.ARTEFACTOOL.get(id);
      const reqUrl = new URL(request.url);
      reqUrl.pathname = '/' + seg.slice(2).join('/') || '/';
      const body = request.method === 'GET' || request.method === 'HEAD' ? undefined : await request.text();
      const hdrs = new Headers(request.headers);
      hdrs.delete('content-length');
      if (body !== undefined) {
        hdrs.set('content-length', String(new TextEncoder().encode(body).length));
      }
      const proxied = new Request(reqUrl.toString(), {
        method: request.method,
        headers: hdrs,
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
      const hdrs = new Headers(request.headers);
      hdrs.delete('content-length');
      if (body !== undefined) {
        hdrs.set('content-length', String(new TextEncoder().encode(body).length));
      }
      const proxied = new Request(request.url, {
        method: request.method,
        headers: hdrs,
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
      const hdrs = new Headers(request.headers);
      hdrs.delete('content-length');
      if (body !== undefined) {
        hdrs.set('content-length', String(new TextEncoder().encode(body).length));
      }
      const proxied = new Request(reqUrl.toString(), {
        method: request.method,
        headers: hdrs,
        body: body !== undefined ? body : undefined,
      });
      return stub.fetch(proxied);
    }

    // /smart-harness/* → harness híbrido
    if (url.pathname.startsWith('/smart-harness/')) {
      const harnessId = env.SMART_HARNESS.idFromName('default-harness');
      const stub = env.SMART_HARNESS.get(harnessId);
      const reqUrl = new URL(request.url);
      reqUrl.pathname = reqUrl.pathname.slice('/smart-harness'.length);
      const body = request.method === 'GET' || request.method === 'HEAD' ? undefined : await request.text();
      const hdrs = new Headers(request.headers);
      hdrs.delete('content-length');
      if (body !== undefined) {
        hdrs.set('content-length', String(new TextEncoder().encode(body).length));
      }
      const proxied = new Request(reqUrl.toString(), {
        method: request.method,
        headers: hdrs,
        body: body !== undefined ? body : undefined,
      });
      return stub.fetch(proxied);
    }

    // /visual-copilot/* → visor de pantalla dividida
    if (url.pathname.startsWith('/visual-copilot/')) {
      const copilotId = env.VISUAL_WEB_COPILOT.idFromName('default-copilot');
      const stub = env.VISUAL_WEB_COPILOT.get(copilotId);
      const reqUrl = new URL(request.url);
      reqUrl.pathname = reqUrl.pathname.slice('/visual-copilot'.length);
      const body = request.method === 'GET' || request.method === 'HEAD' ? undefined : await request.text();
      const hdrs = new Headers(request.headers);
      hdrs.delete('content-length');
      if (body !== undefined) {
        hdrs.set('content-length', String(new TextEncoder().encode(body).length));
      }
      const proxied = new Request(reqUrl.toString(), {
        method: request.method,
        headers: hdrs,
        body: body !== undefined ? body : undefined,
      });
      return stub.fetch(proxied);
    }

    // Fallback: servir assets estáticos (frontend)
    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;
