// Tipos públicos del SDK

export interface BigsoAuthOptions {
    /** Client ID registrado en el SSO */
    clientId: string
    /** Origen del SSO (ej: https://sso.bigso.co) */
    ssoOrigin: string
    /** URL del JWKS para verificar firmas (ej: https://sso.bigso.co/.well-known/jwks.json) */
    jwksUrl: string
    /** Timeout en milisegundos (por defecto 5000) */
    timeout?: number
    /** Activar logs de depuración */
    debug?: boolean
    /** URI de redirección registrada (opcional, si se requiere validación exacta) */
    redirectUri?: string
    /** Sugerencia de tenant (opcional) */
    tenantHint?: string
}

export interface SsoInitPayload {
    state: string
    nonce: string
    code_challenge: string
    code_challenge_method: 'S256'
    origin: string
    redirect_uri?: string
    tenant_hint?: string
    timeout_ms?: number  // permite a la app sobrescribir el timeout del iframe
}

export interface SsoSuccessPayload {
    signed_payload: string
    state: string
}

export interface SsoErrorPayload {
    code: string
    message?: string
    expected_version?: string
}

export type AuthEvents =
    | 'ready'
    | 'success'
    | 'error'
    | 'fallback'
    | 'debug'  // para mensajes de depuración internos