# Reglas de Desarrollo Técnico: artefactools.com

## 1. Configuración Declarativa (`wrangler.jsonc`)
- Usa siempre `wrangler.jsonc` con el schema oficial de 2026 y `observability.enabled: true`.
- Declara los Durable Objects en el bloque `durable_objects.bindings` y en `exports` con `"storage": "sqlite"`.
- Las rutas dinámicas (`/agents/*`, `/api/*`, `/mcp/*`) van en `assets.run_worker_first` para que el Worker las intercepte antes que los estáticos.

## 2. Arquitectura de Estado y Memoria Local
- Todo objeto persistente extiende `DurableObject` e inicializa sus tablas mediante `this.ctx.storage.sql.exec()`.
- Usa Workers RPC para llamadas directas entre el Worker principal y los Durable Objects (`env.USER_SESSION.get(id).fetch(...)`).
- Cada usuario y cada Artefactool es una instancia global única acoplada a su propia base de datos SQLite.

## 3. Ejecución de Código y Seguridad
- Usa `env.LOADER.load` para código JS/TS ligero con `globalOutbound: null` (sin red, sin exfiltración). **Nota:** `worker_loaders` requiere plan de pago de Cloudflare; en despliegues temporales (`--temporary`) se omite la binding.
- Usa `Containers & Sandbox SDK` para entornos Linux, Python, binarios o automatización web.
- La Bóveda de Credenciales nunca expone claves en texto plano al LLM: cifrado AES-GCM con Web Crypto API en SQLite privado, inyección transparente por RPC y aprobaciones humanas para mutaciones críticas (human-in-the-loop).
- Cada `ArtefactoolDO` expone un servidor MCP (`/mcp`) con `tools/list` y `tools/call` para interoperabilidad con agentes externos (Cursor, Claude Desktop, Windsurf, OpenCode).
- Endpoint `/v1/virtualize` permite clonar un repositorio GitHub y desplegarlo como Artefactool aislada.

## 4. Inferencia e Integración de IA
- Usa `env.AI` con `createAI({ binding: env.AI, gateway: "default" })`.
- Smart Harness: Workers AI para subtareas rápidas (JSON, clasificación, resumen); AI Gateway para modelos frontera con fallback automático.
- Capa de monetización: endpoint `/v1/vault/execute` devuelve `403` con `approval_required` cuando se exige aprobación humana antes de mutaciones críticas.

## 5. Comandos de Verificación
- `npx wrangler types` tras cualquier modificación de bindings en `wrangler.jsonc`.
- `npx wrangler deploy` para publicar la plataforma a producción.
- `npx wrangler deploy --temporary` para desplegue sin cuenta (throwaway, 60 min).
- `curl` la URL live tras cada desplegue para verificar que el cuerpo coincide con el código.
