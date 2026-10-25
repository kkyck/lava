/**
 * A compile-time guard for the examples in the README.
 *
 * The file is never executed — the test runner only picks up `*.test.js`
 * files — but the test build compiles it, so a README example that no longer
 * matches the API breaks the build instead of rotting silently.
 */

import { Buffer } from 'node:buffer'

import { WaClient } from '../src/index.js'
import type { MediaHttpHandler } from '../src/index.js'

// The `mediaHttp` example of the README.
const client = new WaClient({
    transport: 'mobile',
    mediaHttp: async (request) => {
        const response = await fetch(request.url, {
            method: request.method,
            headers: request.headers,
            body: request.body ? Buffer.from(request.body) : undefined,
        })
        return {
            status: response.status,
            headers: Object.fromEntries(response.headers),
            body: new Uint8Array(await response.arrayBuffer()),
        }
    },
})

const to = '6281234567890@s.whatsapp.net'
const bytes = new Uint8Array([1, 2, 3])

// The `client.media` example of the README.
const id = await client.message.sendMedia(to, bytes, {
    type: 'image',
    mimetype: 'image/jpeg',
    caption: 'a picture',
    width: 640,
    height: 480,
    fileName: 'picture.jpg',
    seconds: 12,
    ptt: true,
    gifPlayback: true,
})
console.log(id)

const upload = await client.media.upload(bytes, { type: 'image', mimetype: 'image/jpeg' })
const plaintext = await client.media.download(upload)
console.log(plaintext.length)

const handler: MediaHttpHandler = async () => ({
    status: 200,
    headers: {},
    body: new Uint8Array(),
})
console.log(handler)
