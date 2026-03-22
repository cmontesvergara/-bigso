# @bigso/auth-sdk v0.3.0

SDK oficial de autenticación para Bigso SSO, compatible con el estándar SSO v2.3. Este paquete permite integrar aplicaciones web con el flujo de autenticación basado en iframe seguro, utilizando PKCE, JWS firmados y comunicación mediante postMessage.

## 🚀 Características

✅ **Flujo seguro** con PKCE obligatorio y JWS firmado.

✅ **Compatible con SSO v2.3** (whitelist de origins, kid en JWS, validación de nonce, timeout reactivo).

✅ **Manejo automático de estados** (state, nonce, verifier, requestId).

✅ **Verificación de firma JWS** en el frontend usando `jose` y JWKS remoto.

✅ **Timeout reactivo configurable**, activado tras `sso-ready`.

✅ **Soporte para redirect_uri y tenant_hint**.

✅ **Manejo de errores** incluyendo `version_mismatch` con fallback automático.

✅ **API asíncrona** basada en promesas.

✅ **Sistema de eventos** (ready, success, error, fallback, debug).

✅ **Ligero** (~6 kB) y con tipos TypeScript.

## 📦 Instalación

```bash
npm install @bigso/auth-sdk
# o
yarn add @bigso/auth-sdk
# o
pnpm add @bigso/auth-sdk
```

## 🧪 Uso básico

```typescript
import { BigsoAuth } from '@bigso/auth-sdk';

const auth = new BigsoAuth({
  clientId: 'tu-client-id',
  ssoOrigin: 'https://sso.tudominio.com',
  jwksUrl: 'https://sso.tudominio.com/.well-known/jwks.json',
  timeout: 5000,            // opcional, por defecto 5000ms
  debug: true,              // opcional, logs de depuración
  redirectUri: 'https://miapp.com/callback',   // opcional
  tenantHint: 'mi-tenant'   // opcional
});

auth.on('ready', () => console.log('✅ Iframe listo'));
auth.on('success', (payload) => {
  console.log('✅ Autenticación exitosa', payload);
  // Envía el signed_payload al backend para canjear el código
  enviarAlBackend(payload.signed_payload);
});
auth.on('error', (error) => console.error('❌ Error:', error));
auth.on('fallback', () => console.log('⚠️ Fallback por redirección activado'));

auth.login().catch(err => console.error('Login falló', err));
```

## 📚 API Reference

### `new BigsoAuth(options)`
Crea una nueva instancia del cliente de autenticación.

#### Opciones de configuración
| Parámetro | Tipo | Obligatorio | Por defecto | Descripción |
| :--- | :--- | :---: | :---: | :--- |
| `clientId` | `string` | ✅ | — | Client ID registrado en el SSO. |
| `ssoOrigin` | `string` | ✅ | — | Origen del SSO (ej. `https://sso.bigso.co`). |
| `jwksUrl` | `string` | ✅ | — | URL del JWKS para verificar firmas (ej. `/.well-known/jwks.json`). |
| `timeout` | `number` | ❌ | `5000` | Tiempo máximo de espera tras `sso-ready` (milisegundos). |
| `debug` | `boolean` | ❌ | `false` | Activa logs de depuración en consola. |
| `redirectUri` | `string` | ❌ | `''` | URI de redirección registrada (se valida exactamente en el SSO). |
| `tenantHint` | `string` | ❌ | `''` | Sugerencia de tenant para flujos multi-tenant. |

### `auth.login()`
Inicia el flujo de autenticación. Devuelve una promesa que se resuelve con el payload decodificado del JWS (solo para información; la validación final debe realizarse en el backend).

**Retorna**: `Promise<any>` – Payload del JWS (contiene `code`, `state`, `nonce`, `iss`, etc.).

**Rechaza**: `Error` o payload de error del iframe.

### `auth.abort()`
Cancela el flujo de autenticación en curso, eliminando el iframe y rechazando la promesa.

### `auth.on(event, handler)`
Registra un manejador para los eventos del SDK.

#### Eventos disponibles:
| Evento | Descripción | Parámetros |
| :--- | :--- | :--- |
| `ready` | Se emite cuando el iframe está listo y se ha enviado `sso-init`. | — |
| `success` | Se emite tras verificar exitosamente la firma JWS y validar `state`/`nonce` en el frontend. | `payload: any` (payload del JWS) |
| `error` | Se emite cuando ocurre un error (incluyendo `version_mismatch` antes del fallback automático). | `error: Error | SsoErrorPayload` |
| `fallback` | Se emite justo antes de redirigir a la URL de fallback (por timeout o `version_mismatch`). | — |
| `debug` | Se emite cuando `debug: true` para logs internos. | `args: any[]` |

## ⚙️ Ejemplos avanzados

### Personalizar el timeout
```typescript
const auth = new BigsoAuth({
  clientId: 'abc123',
  ssoOrigin: 'https://sso.bigso.co',
  jwksUrl: 'https://sso.bigso.co/.well-known/jwks.json',
  timeout: 10000 // 10 segundos
});
```

### Usar `redirect_uri` y `tenant_hint`
```typescript
const auth = new BigsoAuth({
  clientId: 'abc123',
  ssoOrigin: 'https://sso.bigso.co',
  jwksUrl: 'https://sso.bigso.co/.well-known/jwks.json',
  redirectUri: 'https://admin.miapp.com/callback',
  tenantHint: 'enterprise'
});
```

### Manejo de fallback personalizado
Puedes escuchar el evento `fallback` para ejecutar tu propia lógica antes de la redirección automática:

```typescript
auth.on('fallback', () => {
  console.log('Mostrando spinner o mensaje...');
  // Por defecto, el SDK redirige a /authorize.
  // Si quieres evitar la redirección automática, puedes sobrescribir el comportamiento
  // pero no es recomendable ya que es el mecanismo de último recurso.
});
```

## 🔒 Consideraciones de seguridad

- **Whitelist de origins**: El SDK asume que el SSO Core está configurado correctamente con la whitelist de origins para cada `client_id` y que responde con `Content-Security-Policy: frame-ancestors`. El SDK no puede controlar esto; es responsabilidad del administrador del SSO.
- **Validación en backend**: La verificación del JWS en el frontend es solo una capa adicional de integridad. El backend debe validar la firma, el nonce, el state y canjear el código usando PKCE antes de emitir tokens.
- **nonce y state**: El SDK genera valores aleatorios seguros (`crypto.randomUUID`) y los valida en el frontend. El backend debe realizar la misma validación para prevenir ataques de replay.
- **Prevención de replay**: El SDK no incluye lógica de deduplicación de JWS en el frontend; esto debe implementarse en el backend usando `jti` si es necesario.
- **Timeout**: El timeout se inicia solo después de `sso-ready`, evitando falsos positivos. Si se alcanza, el SDK ejecuta un fallback a redirección (endpoint `/authorize`).
- **Versiones**: El SDK usa `v: '2.3'`. Si el iframe responde con `version_mismatch`, se activa el fallback automático.

## 🛠️ Desarrollo

### Construcción
```bash
npm run build   # genera dist/ con formatos ESM, CJS y types
```

### Pruebas
```bash
npm test        # ejecuta vitest
```

### Linting
```bash
npm run lint
```

## 📝 Changelog

### v0.3.0 (2026-03-21)
Protocolo actualizado a SSO v2.3
- Mensaje `sso-init` con `v: '2.3'`.
- Timeout reactivo (se inicia tras `sso-ready`).
- Validación de `requestId` en respuestas.
- Soporte para `redirect_uri`, `tenant_hint`, `timeout_ms`.
- Manejo de error `version_mismatch` con fallback automático.
- Validación de `nonce` en el frontend tras verificar JWS.

**Mejoras internas:**
- Método `abort()` para cancelar operación.
- Evento `debug` opcional.
- Documentación completa.

**Breaking changes:** Ninguno, pero se recomienda actualizar el backend para validar `nonce` si no lo hacía antes.

### v0.2.0 (anterior)
- Implementación inicial con v2.2.

## 📄 Licencia
MIT © Bigso

## 🤝 Contribuciones
Por favor, abre un issue o pull request en el repositorio oficial.
