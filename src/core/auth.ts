import { sha256Base64Url, generateVerifier, generateRandomId } from '../utils/crypto'
import { EventEmitter } from '../utils/events'
import { verifySignedPayload } from '../utils/jws'
import type { BigsoAuthOptions, SsoInitPayload, SsoSuccessPayload, SsoErrorPayload } from '../types'

export class BigsoAuth extends EventEmitter {
    private options: Required<BigsoAuthOptions>
    private iframe?: HTMLIFrameElement
    private authCompleted = false
    private requestId = generateRandomId()
    private timeoutId?: number
    private messageListener?: (event: MessageEvent) => void
    private abortController?: AbortController

    constructor(options: BigsoAuthOptions) {
        super()
        this.options = {
            timeout: 5000,           // por defecto 5s (estándar v2.3)
            debug: false,
            redirectUri: '',
            tenantHint: '',
            ...options
        }
    }

    /**
     * Inicia el flujo de autenticación.
     * @returns Promise que resuelve con el payload decodificado del JWS (solo para información; el backend debe validar)
     */
    async login(): Promise<any> {
        // Generar y almacenar contexto de la transacción
        const state = generateRandomId()
        const nonce = generateRandomId()
        const verifier = generateVerifier()
        const requestId = this.requestId

        sessionStorage.setItem('sso_ctx', JSON.stringify({ state, nonce, verifier, requestId }))

        // Crear iframe oculto
        this.createIframe()

        return new Promise((resolve, reject) => {
            // Usar AbortController para poder cancelar la promesa externamente
            this.abortController = new AbortController()
            const { signal } = this.abortController

            const cleanup = () => {
                if (this.timeoutId) clearTimeout(this.timeoutId)
                if (this.messageListener) window.removeEventListener('message', this.messageListener)
                this.iframe?.remove()
                this.authCompleted = true
            }

            // Listener de mensajes postMessage
            this.messageListener = async (event: MessageEvent) => {
                // Validación 1: origen exacto (whitelist implícita)
                if (event.origin !== this.options.ssoOrigin) {
                    this.debug('Ignorado mensaje de origen no autorizado:', event.origin)
                    return
                }

                const msg = event.data
                this.debug('Mensaje recibido:', msg)

                // Validación 2: requestId debe coincidir (si está presente)
                if (msg.requestId && msg.requestId !== requestId) {
                    this.debug('requestId no coincide, ignorado')
                    return
                }

                // Evento sso-ready: iniciar timeout y enviar sso-init
                if (msg.type === 'sso-ready') {
                    this.debug('sso-ready recibido, iniciando timeout y enviando sso-init')

                    // Iniciar timeout reactivo (estándar v2.3 sección 7)
                    this.timeoutId = window.setTimeout(() => {
                        if (!this.authCompleted) {
                            this.debug('Timeout alcanzado, activando fallback')
                            this.emit('fallback')
                            window.location.href = this.buildFallbackUrl()
                            reject(new Error('Timeout'))
                            cleanup()
                        }
                    }, this.options.timeout)

                    // Preparar payload sso-init
                    const codeChallenge = await sha256Base64Url(verifier)
                    const initPayload: SsoInitPayload = {
                        state,
                        nonce,
                        code_challenge: codeChallenge,
                        code_challenge_method: 'S256',
                        origin: window.location.origin,
                        ...(this.options.redirectUri && { redirect_uri: this.options.redirectUri }),
                        ...(this.options.tenantHint && { tenant_hint: this.options.tenantHint }),
                        timeout_ms: this.options.timeout  // pasar el timeout configurado (opcional)
                    }

                    // Enviar sso-init al iframe
                    this.iframe?.contentWindow?.postMessage({
                        v: '2.3',                     // versión del protocolo (estándar v2.3)
                        source: '@app/widget',
                        type: 'sso-init',
                        requestId: this.requestId,
                        payload: initPayload
                    }, this.options.ssoOrigin)

                    this.emit('ready')
                    return
                }

                // Evento sso-success
                if (msg.type === 'sso-success') {
                    this.debug('sso-success recibido')
                    clearTimeout(this.timeoutId)

                    try {
                        const payload = msg.payload as SsoSuccessPayload
                        const ctx = JSON.parse(sessionStorage.getItem('sso_ctx') || '{}')

                        // Validar state (comparación en tiempo constante simulada)
                        if (payload.state !== ctx.state) {
                            throw new Error('Invalid state')
                        }

                        // Verificar firma JWS con jose
                        const decoded = await verifySignedPayload(
                            payload.signed_payload,
                            this.options.jwksUrl,
                            window.location.origin  // aud esperado
                        )

                        // Validar nonce (estándar v2.3 sección 8 paso 8)
                        if (decoded.nonce !== ctx.nonce) {
                            throw new Error('Invalid nonce')
                        }

                        // Opcional: validar exp (ya lo hace jose), pero podemos verificar manualmente si se desea
                        // if (decoded.exp && decoded.exp < Math.floor(Date.now() / 1000)) { ... }

                        this.debug('JWS válido, payload:', decoded)

                        // Limpiar y resolver
                        cleanup()
                        this.emit('success', decoded)
                        resolve(decoded)
                    } catch (err) {
                        this.debug('Error en sso-success:', err)
                        cleanup()
                        this.emit('error', err)
                        reject(err)
                    }
                    return
                }

                // Evento sso-error
                if (msg.type === 'sso-error') {
                    const errorPayload = msg.payload as SsoErrorPayload
                    this.debug('sso-error recibido:', errorPayload)
                    clearTimeout(this.timeoutId)

                    // Manejo especial para version_mismatch (estándar v2.3 sección 3.4)
                    if (errorPayload.code === 'version_mismatch') {
                        this.emit('error', errorPayload)
                        // Fallback inmediato a redirección
                        window.location.href = this.buildFallbackUrl()
                        reject(new Error(`Version mismatch: expected ${errorPayload.expected_version}`))
                    } else {
                        this.emit('error', errorPayload)
                        reject(errorPayload)
                    }

                    cleanup()
                }
            }

            window.addEventListener('message', this.messageListener)

            // Manejar señal de aborto (cancelación externa)
            signal.addEventListener('abort', () => {
                this.debug('Operación abortada')
                cleanup()
                reject(new Error('Login aborted'))
            })
        })
    }

    /** Cancela el flujo de autenticación en curso */
    abort() {
        this.abortController?.abort()
    }

    private createIframe() {
        this.iframe = document.createElement('iframe')
        // URL del iframe con versión y client_id (estándar v2.3 sección 1)
        this.iframe.src = `${this.options.ssoOrigin}/embed?v=2.3&client_id=${this.options.clientId}`
        this.iframe.style.display = 'none'
        this.iframe.setAttribute('title', 'SSO iframe')
        document.body.appendChild(this.iframe)
        this.debug('Iframe creado', this.iframe.src)
    }

    private buildFallbackUrl(): string {
        // Construir URL de fallback para redirección (endpoint /authorize con parámetros básicos)
        const url = new URL(`${this.options.ssoOrigin}/authorize`)
        url.searchParams.set('client_id', this.options.clientId)
        url.searchParams.set('response_type', 'code')
        url.searchParams.set('redirect_uri', this.options.redirectUri || window.location.origin)
        url.searchParams.set('state', generateRandomId())
        url.searchParams.set('code_challenge_method', 'S256')
        // Nota: en un flujo real se debería generar code_challenge, pero en fallback se redirige
        // y luego la app debe manejar el callback. Simplificamos.
        return url.toString()
    }

    private debug(...args: any[]) {
        if (this.options.debug) {
            console.log('[BigsoAuth]', ...args)
        }
    }
}