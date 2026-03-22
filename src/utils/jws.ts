// Verificación de JWS usando jose (soporta kid automáticamente)
import { jwtVerify, createRemoteJWKSet } from 'jose'

export async function verifySignedPayload(
    token: string,
    jwksUrl: string,
    expectedAudience: string
) {
    const JWKS = createRemoteJWKSet(new URL(jwksUrl))

    const { payload } = await jwtVerify(token, JWKS, {
        audience: expectedAudience
    })

    return payload
}