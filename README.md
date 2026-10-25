# wa-lite

**An ultra-lightweight, zero-dependency WhatsApp client library for Node.js.**

`wa-lite` speaks WhatsApp's protocol directly — the native **mobile (WAP) API**
by default, the **WhatsApp Web** API optionally — and implements the Signal
double ratchet, the Noise handshake, the binary node codec and the protobuf
schema itself. There is **no runtime dependency at all**: the only thing you
need is Node.js 22.

```ts
import { WaClient } from 'wa-lite'

const client = new WaClient({ transport: 'mobile' })

client.on('message', (m) => console.log(`${m.jid}: ${m.text}`))
client.on('auth_qr', ({ qr }) => console.log(qr))

await client.connect()
await client.message.send('6281234567890@s.whatsapp.net', 'Hello from wa-lite')
```

---

## Table of contents

- [Why wa-lite](#why-wa-lite)
- [Install](#install)
- [Quick start](#quick-start)
- [Mobile vs. Web mode](#mobile-vs-web-mode)
- [Pairing](#pairing)
- [API reference](#api-reference)
  - [`client.message`](#clientmessage)
- [`client.media`](#clientmedia)
- [`client.group`](#clientgroup)
  - [`client.profile`](#clientprofile)
  - [`client.presence`](#clientpresence)
  - [`client.privacy`](#clientprivacy)
  - [`client.call`](#clientcall)
  - [`client.auth`](#clientauth)
  - [Events](#events)
- [Credentials](#credentials)
- [Security](#security)
- [Memory footprint](#memory-footprint)
- [Architecture](#architecture)
- [Development](#development)
- [License](#license)

---

## Why wa-lite

| | wa-lite | Baileys | Zapo |
| --- | --- | --- | --- |
| Runtime dependencies | **0** | 12+ | 20+ |
| Native mobile (WAP) API | ✅ | ❌ | ✅ |
| WhatsApp Web API | ✅ | ✅ | ✅ |
| Own protobuf codec | ✅ (schema-driven) | protobufjs | protobufjs |
| Own Signal implementation | ✅ | `@whiskeysockets/baileys` | `@whiskeysockets/baileys` |
| Own Noise handshake | ✅ | ✅ | ✅ |
| Media upload / download | ✅ | ✅ | ✅ |
| Calls (signalling) | ✅ | ⚠️ partial | ⚠️ partial |
| Bundle size | **~770 KB** raw JS | ~2.5 MB | ~4 MB |

**Zero dependencies means zero supply-chain risk.** Everything — the protobuf
codec, the Signal double ratchet, XEdDSA, the Noise handshake, the QR encoder
— is implemented here against Node's built-in `node:crypto`. There is no
`protobufjs` reflection model, no `libsignal` WASM blob and no `qrcode`
dependency.

---

## Install

```bash
npm install wa-lite
```

Node.js **22 or newer** is required (`node:crypto`'s X25519 support and
`node:test`).

To work on the library itself:

```bash
npm install       # dev dependencies only (typescript, @types/node)
npm run build     # compile to dist/
npm test          # compile and run the test suite
```

---

## Quick start

```ts
import { WaClient, FileCredentialStore } from 'wa-lite'

const client = new WaClient({
    // `mobile` uses the native WAP API (the default); `web` uses WhatsApp Web.
    transport: 'mobile',
    // Persist the session so the device does not have to be paired again.
    credentials: new FileCredentialStore('./session.json'),
    pushName: 'wa-lite',
})

client.on(WaClient.AUTH_QR, ({ qr }) => console.log('Scan this:', qr))
client.on(WaClient.MESSAGE, (message) => {
    console.log(message.fromMe ? 'sent' : 'received', message.text)
})
client.on(WaClient.RECEIPT, ({ id, type }) => console.log(id, type))
client.on(WaClient.ERROR, (error) => console.error(error))

await client.connect()

const id = await client.message.send('6281234567890', 'Hello')
console.log('sent', id)
```

`connect()` resolves as soon as the Noise handshake succeeded and the server
accepted the client payload. Pairing (if needed) continues in the background
and completes through the `auth_paired` event.

---

## Mobile vs. Web mode

| | `transport: 'mobile'` (default) | `transport: 'web'` |
| --- | --- | --- |
| Endpoint | `g.whatsapp.net:443` (TCP) | `wss://web.whatsapp.com/ws/chat` |
| Reported platform | Android / iOS | Desktop browser |
| Message id format | 32 hex chars, first byte `0xac` | 22 chars, prefix `3EB0` |
| Client payload | `ClientPayload` with a `DeviceProps` blob | `ClientPayload` with `WebInfo` |
| Bans | Fewer — indistinguishable from the official app | More likely, the web app is fingerprinted harder |

The mobile transport is the default because it is the one that survives
server-side fingerprinting: the server sees a stock Android build with a
plausible device profile, not a headless browser.

```ts
const client = new WaClient({ transport: 'web' })
```

Both modes share **the same** wire format underneath: the binary node codec,
the stanza framing and the Signal encryption are identical. Only the socket
and the client payload differ.

---

## Pairing

A companion device has to be linked to a phone once. Two flows are supported.

### QR code

The client emits an `auth_qr` event with the payload the phone's
*Link a device* screen expects. Render it with the bundled encoder:

```ts
import { WaClient, encodeQr, qrToTerminal } from 'wa-lite'

client.on(WaClient.AUTH_QR, ({ qr }) => {
    console.log(qrToTerminal(encodeQr(qr)))
})
```

The payload is the comma-separated format the official client uses:

```text
<ref>,<base64 noise pubkey>,<base64 identity pubkey>,<base64 adv secret>,<platform>
```

### Pairing code

```ts
const code = await client.auth.requestPairingCode('6281234567890')
console.log('Enter this code on your phone:', code)
```

The code is eight Crockford base32 characters. It is stretched with
PBKDF2-SHA256 (131 072 iterations) into the key that unwraps the phone's
ephemeral public key, so the code never travels over the network.

---

## API reference

### `client.message`

```ts
// Send a text message.
const id = await client.message.send(to, 'Hello', {
    quote: { remoteJid, fromMe: false, id: 'MSGID' },
    mentionedJid: ['628...@s.whatsapp.net'],
    linkPreview: { url: 'https://example.com', title: 'Example' },
})

// Send a pre-built body.
await client.message.sendBody(to, { conversation: 'raw' })

// React, revoke, location, contact, poll.
await client.message.react(to, target, '👍')
await client.message.revoke(to, target)
await client.message.sendLocation(to, { latitude: 1.5, longitude: 2.5 })
await client.message.sendContact(to, { displayName: 'Alice', vcard: '…' })
await client.message.createPoll(to, { name: 'Lunch?', options: [{ name: 'Pizza' }] })

// Mark a chat as read.
await client.message.read(to, { id: 'LAST_MESSAGE_ID' })
```

### `client.media`

Media is encrypted with a per-file key (AES-256-CBC plus a truncated
HMAC-SHA256, both derived with HKDF-SHA256), uploaded to the WhatsApp CDN and
referenced from the message stanza. The upload token and the CDN hosts come
from the server's `media_conn` answer, which is cached until the token
expires.

```ts
// Send a picture, a video, a voice note, a document, a GIF or a sticker.
const id = await client.message.sendMedia(to, bytes, {
    type: 'image',                       // image | video | audio | ptt | document | gif | sticker
    mimetype: 'image/jpeg',
    caption: 'a picture',
    width: 640,
    height: 480,
    fileName: 'picture.jpg',             // documents only
    seconds: 12,                         // audio, video and voice notes
    ptt: true,                           // voice notes
    gifPlayback: true,                   // GIFs
})

// Or drive the two halves separately.
const upload = await client.media.upload(bytes, { type: 'image', mimetype: 'image/jpeg' })
const plaintext = await client.media.download(upload)
```

`client.media.download` accepts an inbound message, a raw message body, a
media payload or the result of an upload, and returns the decrypted bytes.
The download tries the hosts the media connection named before falling back to
the well known CDN hosts.

To plug in your own HTTP stack — for a proxy, a cache or a test — pass a
`mediaHttp` handler:

```ts
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
```

### `client.group`

```ts
await client.group.create('Subject', ['628…@s.whatsapp.net'], 'Description')
await client.group.addParticipants(groupJid, ['628…@s.whatsapp.net'])
await client.group.removeParticipants(groupJid, ['628…@s.whatsapp.net'])
await client.group.promoteParticipants(groupJid, ['628…@s.whatsapp.net'])
await client.group.demoteParticipants(groupJid, ['628…@s.whatsapp.net'])
await client.group.setSubject(groupJid, 'New subject')
await client.group.leave([groupJid])
```

### `client.profile`

```ts
await client.profile.setPushName('New name')
await client.profile.setStatus('Available')
const profile = await client.profile.get('628…@s.whatsapp.net')
```

### `client.presence`

```ts
client.presence.available('My Name')
client.presence.unavailable()
client.presence.chatState(to, 'composing')
```

### `client.privacy`

```ts
await client.privacy.getSettings()
await client.privacy.setCategory('last', 'contacts')
await client.privacy.getBlocked('blocklist')
await client.privacy.setBlocked('blocklist', ['628…@s.whatsapp.net'])
```

### `client.call`

The call API implements the `<call>` / `<offer>` / `<accept>` / `<reject>`
signalling protocol. The media plane is pluggable — pass your own SDP and
transport.

```ts
const callId = await client.call.offer(to, { video: true })
await client.call.accept(to, callId, { media: { sdp } })
await client.call.reject(to, callId)
await client.call.terminate(to, callId)
```

### `client.auth`

```ts
await client.auth.requestPairingCode('6281234567890')
await client.auth.fetchCountryCode()
client.auth.getCurrentCredentials()
await client.auth.logout()
```

### Events

`WaClient` extends `EventEmitter`.

| Event | Payload |
| --- | --- |
| `auth_qr` | `{ qr, ttlMs }` |
| `auth_pairing_code` | `{ code }` |
| `auth_paired` | `{ meJid, meLid }` |
| `connection` | `{ state }` — `disconnected`, `connecting`, `pairing`, `connected`, `closing` |
| `message` | `WaInboundMessage` |
| `message_ack` | `WaMessageAck` |
| `receipt` | `WaReceipt` |
| `call` | `WaCallEvent` |
| `error` | `Error` |

### Plugging in your own transport

`transportFactory` replaces the socket layer. The factory receives the Noise
handshake context — the client payload and the key material — and returns a
`WaTransport`:

```ts
interface WaTransport {
    start(): Promise<void>
    send(node: BinaryNode): void
    query(node: BinaryNode, timeoutMs?: number): Promise<BinaryNode>
    getServerStaticKey(): Uint8Array | null
    close(): void
}

const client = new WaClient({
    transportFactory: ({ noise, handlers }) => ({
        start: async () => { /* open the socket, feed the Noise payload */ },
        send: (node) => { /* write the stanza */ },
        query: async (node) => { /* round-trip an IQ */ },
        getServerStaticKey: () => null,
        close: () => { /* tear the socket down */ },
    }),
})
```

This is what the test suite uses to drive the whole pipeline — pairing,
device-list lookup, pre-key fetch, Signal encryption, stanza building and
inbound decryption — without touching the network.

---

## Credentials

The session is stored through a `CredentialStore`. Two implementations ship
with the library:

```ts
import { MemoryCredentialStore, FileCredentialStore } from 'wa-lite'

new MemoryCredentialStore()          // in-memory, gone on restart
new FileCredentialStore('./wa.json')  // persisted to disk
```

A snapshot contains the Noise identity key pair, the Signal identity key
pair, the signed pre-key, the unused one-time pre-keys and the account's JID.
Implement the `CredentialStore` interface to put it in a database, a
keychain or an encrypted blob.

The one-time pre-keys are handed out with **sequential ids**, exactly like the
official clients do, so they are unique inside the device and always fit the
three byte field the protocol uses for them. Signed pre-keys live in their own
id namespace, so a signed pre-key may reuse the number of a one-time pre-key
without any ambiguity.

The snapshot also keeps the upload cursor (`firstUnuploadedPreKeyId`), so a
pre-key is never uploaded twice, and the uploaded pre-keys stay in the
snapshot: the server keeps handing them out, and the device must still be
able to decrypt the pre-key message that uses them. A pre-key that was
consumed is dropped immediately, so it can never be replayed.

### The pre-key lifecycle

The whole pre-key lifecycle follows the official clients:

| Step | What happens |
| --- | --- |
| Pairing | A signed pre-key is generated and a full batch of **812** one-time pre-keys is created. |
| Upload | The whole batch travels in a single `<iq type="set" xmlns="encrypt">`. |
| Afterwards | `serverHasPreKeys` is set, so no second batch is uploaded — the server hands the pre-keys out one by one. |
| Server runs low | The server sends `<notification type="encrypt"><count/></notification>`; the client acknowledges it, clears the flag and uploads a fresh batch. |
| Drift detected | The server sends `<notification type="encrypt"><digest/></notification>` (or rejects a signed pre-key rotation); the client asks for the server's key digest, compares it with its own state and repairs the drift with a fresh batch. |
| Consumption | A pre-key that is used is dropped from the pool at once and can never be replayed. |

The pool is bounded at 4096 pre-keys; the oldest uploaded ones are dropped
first, so a long-lived device never piles up key material.

---

## Security

- **End-to-end encryption** is implemented from scratch: the Signal double
  ratchet with XEdDSA-signed pre-keys, half-double ratcheting, skipped-key
  handling and the sender-key (group) protocol.
- **The message secret** (32 bytes per message) is attached to every message
  body. Poll votes, reactions and edits derive their own key from it with
  HKDF, so a modification can be decrypted without revealing the original
  message.
- **Padding**: every plaintext is padded with 1–16 random bytes before
  encryption, hiding the exact message length.
- **Forward compatibility**: unknown protobuf fields are skipped, and a known
  field whose wire type does not match the schema is skipped rather than
  mis-parsed, so a hostile server cannot crash the parser.
- **Authenticated encryption**: AES-256-GCM is used everywhere with the
  authentication tag verified *before* the plaintext is returned.
- **One-time pre-keys** are consumed exactly once and removed from the pool.

> **Note.** This library is an unofficial client. Use it in accordance with
> WhatsApp's Terms of Service. The authors cannot guarantee that the
> protocol will not change, and using an unofficial client may result in
> your account being banned.

---

## Memory footprint

`npm run bench` measures the resident set size of the library:

```
wa-lite memory benchmark
===================================================
baseline (Node + library)    70.46 MB RSS
+ 1 Signal session           73.57 MB RSS
+ full pre-key pool (812)    75.45 MB RSS
===================================================
session cost      3.11 MB
pre-key pool cost 1.88 MB (812 pre-keys, 2.4 KB each)
heap growth       3.13 MB
upload batch      812 pre-keys per upload
ciphertext        151 bytes
schema            511 messages / 2427 fields
```

The library itself adds roughly **3 MB** to a Node.js process, most of which
is the 511-message protobuf schema and the V8 heap churn of the benchmark
itself. A single Signal session costs well under a megabyte of live key
material.

`npm run size` reports the code size:

```
compiled javascript    769.9 KB
type declarations       267.8 KB
typescript sources     868.3 KB

breakdown by module
----------------------------------------------
proto        221.5 KB
transport    191.0 KB
signal        97.4 KB
(root)        84.7 KB
protocol      50.0 KB
crypto        40.6 KB
qr            35.0 KB
media         22.3 KB
message       12.3 KB
auth           9.2 KB
util           5.9 KB
----------------------------------------------

runtime dependencies          0
```

---

## Architecture

```
src/
├── client.ts          the WaClient orchestrator: lifecycle, routing, dispatch
├── auth/              credentials and the pairing handshake
├── crypto/            primitives, XEdDSA, the Noise handshake
├── message/           the message codec: padding, secrets, body extraction
├── proto/             the schema-driven protobuf codec (511 messages)
├── protocol/          JID helpers, message bodies, protocol constants
├── qr/                the QR encoder and the WhatsApp pairing payload
├── signal/            the double ratchet, key store, group sender keys
├── transport/         binary node codec, noise session, tcp/websocket, web/mobile
└── util/              base64 and message-id helpers
```

The transport layer is transport-agnostic: a `Connection` owns the Noise
session and takes `sendWire` / `closeWire` callbacks, so the same protocol
code drives both the TCP and the WebSocket transport.

The protobuf codec compiles each message into a flat field-descriptor table
at load time and encodes straight against the wire format — no reflection
model, no code generation at runtime, one output buffer per message.

---

## Development

```bash
npm run typecheck   # tsc --noEmit
npm run build       # compile to dist/
npm test            # 185 tests
npm run bench       # memory benchmark
npm run size        # size report
```

The protobuf schema is generated from the wire definitions of the current
WhatsApp clients:

```bash
node scripts/generate-schema.cjs
node scripts/validate-schema.cjs
```

---

## License

MIT
