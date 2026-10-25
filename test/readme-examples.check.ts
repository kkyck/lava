/**
 * A compile-time guard for the examples in the README.
 *
 * The file is never executed — the test runner only picks up `*.test.js`
 * files — but the test build compiles it, so a README example that no longer
 * matches the API breaks the build instead of rotting silently.
 */

import { Buffer } from 'node:buffer'

import { LavaClient } from '../src/index.js'
import type { MediaHttpHandler } from '../src/index.js'

// The `mediaHttp` example of the README.
const client = new LavaClient({
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

// The `client.appState` example of the README.
const result = await client.appState.sync({
    collections: ['regular', 'regular_low'],
})
for (const entry of result.collections) {
    console.log(entry.collection, entry.state, entry.version, entry.uploaded)
}
console.log(result.missingKeyIds)

client.appState.set('regular', 'the-index', { pushNameSetting: { name: 'Lava' } })
client.appState.remove('regular', 'the-other-index')

console.log(client.appState.keys())
console.log(client.appState.state('regular'))

const otherDeviceJid = '6281234567890:1@s.whatsapp.net'
const missingKeyId = new Uint8Array(6)
await client.appState.share(otherDeviceJid)
await client.appState.request(otherDeviceJid, [missingKeyId])

// The `client.registration` example of the README.
await client.registration.requestCode('6281234567890', { method: 'sms' })
await client.registration.confirm('123456')
await client.registration.status('6281234567890')

// The `client.auth` example of the README.
await client.auth.requestPairingCode('6281234567890')
await client.auth.fetchCountryCode()
client.auth.getCurrentCredentials()

// The `client.group` example of the README.
await client.group.create('Subject', ['6281234567890@s.whatsapp.net'], 'Description')
await client.group.addParticipants('120363000000000000@g.us', [
    '6281234567890@s.whatsapp.net',
])
await client.group.setSubject('120363000000000000@g.us', 'New subject')

// The `client.presence` example of the README.
client.presence.available('My Name')
client.presence.unavailable()
client.presence.chatState(to, 'composing')
