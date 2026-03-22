// Funciones criptográficas seguras

export async function sha256Base64Url(input: string): Promise<string> {
    const encoder = new TextEncoder()
    const data = encoder.encode(input)
    const digest = await crypto.subtle.digest('SHA-256', data)
    return base64Url(new Uint8Array(digest))
}

export function generateVerifier(length = 32): string {
    const array = new Uint8Array(length)
    crypto.getRandomValues(array)
    return base64Url(array)
}

export function base64Url(bytes: Uint8Array): string {
    return btoa(String.fromCharCode(...bytes))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '')
}

export function generateRandomId(): string {
    return crypto.randomUUID()
}