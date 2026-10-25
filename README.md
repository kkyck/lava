# Lava

**An ultra-lightweight, zero-dependency WhatsApp client library for Node.js.**

Lava speaks WhatsApp's protocol directly — the native **mobile (WAP) API** by
default, the **WhatsApp Web** API optionally — and implements the Signal
double ratchet, the Noise handshake, the binary node codec and the protobuf
schema itself. There is **no runtime dependency at all**: the only thing you
need is Node.js 22.

```ts
import { LavaClient } from 'lava'

const client = new LavaClient({ transport: 'mobile' })

client.on('message', (m) => console.log(`${m.jid}: ${m.text}`))
client.on('auth_qr', ({ qr }) => console.log(qr))

await client.connect()
await client.message.send('6281234567890@s.whatsapp.net', 'Hello from Lava')
```

---

## Table of contents

- [Why Lava](#why-lava)
- [Install](#install)
- [Quick start](#quick-start)
- [Mobile vs. Web mode](#mobile-vs-web-mode)
- [Registering a phone number](#registering-a-phone-number)
- [Pairing as a companion device](#pairing-as-a-companion-device)
- [API reference](#api-reference)
  - [`client.message`](#clientmessage)
  - [`client.media`](#clientmedia)
  - [`client.appState`](#clientappstate)
  - [`client.group`](#clientgroup)
  - [`client.profile`](#clientprofile)
  - [`client.presence`](#clientpresence)
  - [`client.privacy`](#clientprivacy)
  - [`client.call`](#clientcall)
  - [`client.auth`](#clientauth)
  - [`client.registration`](#clientregistration)
  - [Events](#events)
- [Delivery guarantees](#delivery-guarantees)
- [Credentials](#credentials)
- [Security](#security)
- [Memory footprint](#memory-footprint)
- [Architecture](#architecture)
- [Development](#development)
- [Notices](#notices)
- [License](#license)

---

## Why Lava

| | Lava | Baileys | Zapo |
| --- | --- | --- | --- |
| Runtime dependencies | **0** | 12+ | 20+ |
| Native mobile (WAP) API | ✅ | ❌ | ✅ |
| WhatsApp Web API | ✅ | ✅ | ✅ |
| Own protobuf codec | ✅ (schema-driven) | protobufjs | protobufjs |
| Own Signal implementation | ✅ | `@whiskeysockets/baileys` | `@whiskeysockets/baileys` |
| Own Noise handshake | ✅ | ✅ | ✅ |
| Phone-number registration (SMS) | ✅ | ❌ | ❌ |
| Media upload / download | ✅ | ✅ | ✅ |
| App-state sync (chat list, contacts) | ✅ | ⚠️ partial | ✅ |
| Calls (signalling) | ✅ | ⚠️ partial | ⚠️ partial |
| Group sender keys | ✅ 5 generations | ✅ 5 generations | ⚠️ 1 generation |
| Bundle size | **~1.01 MB** raw JS | ~2.5 MB | ~4 MB |

**Zero dependencies means zero supply-chain risk.** Everything — the protobuf
codec, the Signal double ratchet, XEdDSA, the Noise handshake, the QR encoder —
is implemented here against Node's built-in `node:crypto`. There is no
`protobufjs` reflection model, no `libsignal` WASM blob and no `qrcode`
dependency.

Lava is also **mobile-first**: the default transport is the native WAP API, the
one the official Android and iOS apps speak. A device that talks to the server
over the mobile protocol with a plausible device fingerprint is
indistinguishable from the official app, which is why mobile mode is the
default rather than an afterthought.

---

## Install

```bash
npm install github:kkyck/lava
```

Node.js **22 or newer** is required (`node:crypto`'s X25519 support and
`node:test`).

> The name `lava` on the npm registry belongs to an unrelated package, so the
> library is installed straight from the repository. It has **no runtime
> dependencies** either way — the only thing you need is Node.js 22.

To work on the library itself:

```bash
git clone https://github.com/kkyck/lava
cd lava
npm install       # dev dependencies only (typescript, @types/node)
npm run build     # compile to dist/
npm test          # compile and run the test suite
```

---

## Quick start

```ts
import { LavaClient, FileCredentialStore } from 'lava'

const client = new LavaClient({
    // `mobile` uses the native WAP API (the default); `web` uses WhatsApp Web.
    transport: 'mobile',
    // Persist the session so the device does not have to be paired again.
    credentials: new FileCredentialStore('./session.json'),
    pushName: 'Lava',
})

client.on(LavaClient.AUTH_QR, ({ qr }) => console.log('Scan this:', qr))
client.on(LavaClient.MESSAGE, (message) => {
    console.log(message.fromMe ? 'sent' : 'received', message.text)
})
client.on(LavaClient.RECEIPT, ({ id, type }) => console.log(id, type))
client.on(LavaClient.ERROR, (error) => console.error(error))

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
const client = new LavaClient({ transport: 'web' })
```

Both modes share **the same** wire format underneath: the binary node codec,
the stanza framing and the Signal encryption are identical. Only the socket
and the client payload differ.

The device profile is persisted with the session, so a reconnect keeps the same
device identity. Override it explicitly if you want to:

```ts
const client = new LavaClient({
    transport: 'mobile',
    deviceProfile: {
        appVersion: '2.26.42.71',
        device: 'Redmi Note 12',
        osVersion: '13',
        osBuildNumber: 'TQ3A.230901.001',
        manufacturer: 'Xiaomi',
        os: 'android',
    },
})
```

The server refuses a client it considers too old with the reason **405**, so
the reported version has to be one the server still accepts. The defaults
(`2.26.42.71` for the mobile transports, `2.3000.1094123276` for the web
transport) are the newest builds that were measured to work.

---

## Registering a phone number

Lava can claim a phone number as a **primary mobile device**, the way the
official app does after a fresh install. This is the flow the server exposes on
the mobile API:

```text
/exist → /code → /register
```

`/exist` checks whether the number is free, `/code` asks the server to send a
verification code by SMS (or voice call), and `/register` claims the number
with the code the user received.

```ts
import { LavaClient } from 'lava'

const client = new LavaClient({ transport: 'mobile' })

client.on(LavaClient.AUTH_REGISTRATION_CODE, ({ phoneNumber, method, length }) => {
    console.log(`a ${method} code of ${length} digits was sent to ${phoneNumber}`)
})
client.on(LavaClient.AUTH_REGISTERED, ({ meJid }) => {
    console.log('registered as', meJid)
})

await client.connect()

// The number must be in international format: country code first.
await client.registration.requestCode('6281234567890', { method: 'sms' })

// …the user receives a six digit code…
const result = await client.registration.confirm('123456')
console.log(result.ok, result.canonicalNumber)
```

The phone number **must** carry a country code. A national number is rejected
with `has no country code`, because the server files the account under the
international form.

### `/exist` is advisory

The `/exist` endpoint answers most requests with a refusal — measured live, a
request the server refuses comes back with the same answer for *every* number,
registered or not. Such an answer says nothing about the number, so Lava
reports it as inconclusive instead of guessing:

```ts
const status = await client.registration.status('6281234567890')
if (status.conclusive && status.registered) {
    // the number is an account — pair as a companion instead
}
```

The truth comes from `/code`: it is the endpoint that decides. A number that
cannot receive a code is refused there, and a number that already exists is
refused as well.

### A code that arrives after a restart

The code arrives by SMS, which can take minutes — by the time it does, the
process that asked for it may be gone. The material of the registration is
therefore kept with the session, so a restarted client can still hand the code
back:

```ts
// a fresh process, with the same credential store
const client = new LavaClient({ transport: 'mobile', credentials: store })
await client.registration.confirm('123456')
```

### Platforms

| Platform | Token | Notes |
| --- | --- | --- |
| `ios` (default) | derived | The static token plus `md5(appVersion ‖ national number)`. |
| `android` | caller supplied | The Android token is derived from a signed APK, so bring your own. |

```ts
await client.registration.requestCode('6281234567890', {
    os: 'android',
    token: 'a1b2c3…',
})
```

The registration announces the very same device the connection announces
afterwards — a client without a device profile registers as an iPhone, and
the session that follows announces that iPhone.

### How the requests are signed

The registration endpoints live on `https://v.whatsapp.net/v2/…` and expect an
encrypted envelope instead of a plain form body:

```text
ENC = base64url(ephemeral X25519 public key ‖ AES-256-GCM(shared secret, zero IV) ‖ tag)
```

The form body is `key=value&…` with **no** percent-encoding, and the `id`
parameter uses the Java `toUrlHex` encoding (`%AA%BB`). Lava implements this
from the protocol; no third-party client is involved.

---

## Pairing as a companion device

A companion device has to be linked to a phone once. Two flows are supported.

### QR code

The client emits an `auth_qr` event with the payload the phone's
*Link a device* screen expects. Render it with the bundled encoder:

```ts
import { LavaClient, encodeQr, qrToTerminal } from 'lava'

client.on(LavaClient.AUTH_QR, ({ qr }) => {
    console.log(qrToTerminal(encodeQr(qr)))
})
```

The payload is the comma-separated format the official client uses:

```text
<ref>,<base64 noise pubkey>,<base64 identity pubkey>,<base64 adv secret>,<client type>
```

The last field is the client type of the linking program — `1` for a browser.

The server hands out a handful of references, each of which is valid for a
limited time. The client walks through them and emits a new `auth_qr` event
as the current one expires — the first reference of a set lives for a minute,
the following ones for twenty seconds each. The attestation secret is
rotated with every set, so a leaked QR code cannot be replayed.

While the phone scans, the client keeps the socket alive: WhatsApp closes a
connection that stays silent, so the client pings the server every few
seconds and re-establishes the connection when a ping goes unanswered.

### Pairing code

```ts
const code = await client.auth.requestPairingCode('6281234567890')
console.log('Enter this code on your phone:', code)
```

On the phone the code goes into **Settings → Linked devices → Link a device
→ Link with phone number instead**.

The code is eight Crockford base32 characters. It is stretched with
PBKDF2-SHA256 (131 072 iterations) into the key that unwraps the phone's
ephemeral public key, so the code never travels over the network.

The client announces itself as the program that links — a browser, with the
system it runs on — because the server only accepts the browser client types
for this protocol. The number of pairing codes a phone may ask for is
limited; a request that runs into the limit is answered with
`429 rate-overlimit`, and the caller is expected to wait before it asks
again.

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

// Edit a message that was sent earlier — the recipient sees the new text
// in place of the old one.
await client.message.edit(to, target, 'fixed typo')

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
```

### `client.appState`

WhatsApp keeps the chat list, the contacts, the labels and the mute and
archive settings of an account in sync between its devices. The server only
brokers the changes: every record is encrypted with a per-device *sync key*
and MACed, and a digest (the LT-hash) proves that two devices hold the same
collection without the server reading any of it.

Lava speaks that protocol directly — the same key derivation
(`WhatsApp Mutation Keys`), the same AES-256-CBC value encryption, the same
HMAC-SHA-512 value MAC and the same 128-byte LT-hash as the official
clients, so a Lava device and an official device can share the same
collection state.

```ts
// Synchronise the collections of the account.
const result = await client.appState.sync({
    collections: ['regular', 'regular_low'],
})
for (const entry of result.collections) {
    console.log(entry.collection, entry.state, entry.version, entry.uploaded)
}

// Record a change; the next round pushes it to the server.
client.appState.set('regular', 'the-index', { pushNameSetting: { name: 'Lava' } })
client.appState.remove('regular', 'the-other-index')

// The sync keys and the collection state survive a restart.
console.log(client.appState.keys())
console.log(client.appState.state('regular'))

// Move the sync keys between the devices of an account.
await client.appState.share(otherDeviceJid)
await client.appState.request(otherDeviceJid, [missingKeyId])
```

The client synchronises the app state in the background right after it
connects, and imports the keys a peer shares with it.

#### Conflicts

Two devices of the same account can change the same collection while both are
offline. The server then reports a **conflict**, and Lava handles it the way
the official clients do:

| Situation | `state` | `uploaded` | What happens |
| --- | --- | --- | --- |
| No local change pending | `success` | `true` | The server state wins; the device is aligned. |
| A local change is pending | `conflict` | `false` | The server state is applied, the pending change is **held back** and re-queued for the next round. |

`uploaded` defaults to `pendingCount === 0`: a round that had nothing to push
reports `uploaded: true`.

The conflict state is **sticky** across rounds, so a collection that is in
conflict keeps reporting `conflict` until it is resolved — a client can rely
on the flag instead of diffing the versions itself.

`result.missingKeyIds` lists the sync keys the server needed but the device
does not have. The client asks the other devices of the account for them
through `client.appState.request`.

### `client.group`

```ts
await client.group.create('Subject', ['628…@s.whatsapp.net'], 'Description')
await client.group.addParticipants(groupJid, ['628…@s.whatsapp.net'])
await client.group.removeParticipants(groupJid, ['628…@s.whatsapp.net'])
await client.group.promoteParticipants(groupJid, ['628…@s.whatsapp.net'])
await client.group.demoteParticipants(groupJid, ['628…@s.whatsapp.net'])
await client.group.setSubject(groupJid, 'New subject')
await client.group.leave([groupJid])

// The member list and the settings of the group.
const metadata = await client.group.metadata(groupJid)
const members = await client.group.participants(groupJid)

// The group server refuses a client that asks for the member list of the
// same group over and over, so the answer is cached — and it survives a
// restart, so a fresh process is not refused either. Drop the cache when the
// membership really changed.
client.group.refresh(groupJid)

// A member that never got a usable sender key can be repaired without
// waiting for a re-key: the distribution is sent again with the next message.
client.group.redistributeSenderKey(groupJid)

// A new generation of the sender key of the group. The replaced generation
// is kept, so a message that was encrypted with it can still be read.
const keyId = client.group.rotateSenderKey(groupJid)
```

#### Addressing mode

A group either names its members by their phone number or by their *linked
identity* (LID). The mode is not cosmetic: the sender key of a group belongs
to the address the group uses, and the `addressing_mode` attribute of the
stanza tells the server how the addresses in it have to be read — a group
message that leaves the attribute out, or carries the wrong one, is not
delivered to the members.

Lava reads the mode from the member list of the group and sends the attribute
with every group stanza. The member list is read from the group server
(`w:g2`), and it is cached — the server refuses a client that asks for the
same group over and over.

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

An inbound call is announced through the `call` event:

```ts
client.on('call', (event) => {
    // event.id, event.jid, event.video, event.direction, event.status
    // event.status is one of 'offer', 'accept', 'reject', 'terminate'
})
```

Lava answers the stanza itself, so the peer considers the call delivered: an
offer, an accept, a reject and a re-key are answered with a receipt that
carries the payload back, every other payload with a plain acknowledgement.

### `client.auth`

```ts
await client.auth.requestPairingCode('6281234567890')
await client.auth.fetchCountryCode()
client.auth.getCurrentCredentials()
await client.auth.logout()
```

### `client.registration`

```ts
await client.registration.requestCode('6281234567890', { method: 'sms' })
await client.registration.confirm('123456')
await client.registration.status('6281234567890')
```

See [Registering a phone number](#registering-a-phone-number) for the details.

### Events

`LavaClient` extends `EventEmitter`.

| Event | Payload |
| --- | --- |
| `auth_qr` | `{ qr, ttlMs }` |
| `auth_pairing_code` | `{ code }` |
| `auth_paired` | `{ meJid, meLid }` |
| `auth_registration_code` | `{ phoneNumber, method, length, wait }` |
| `auth_registered` | `{ meJid }` |
| `connection` | `{ state }` — `disconnected`, `connecting`, `pairing`, `connected`, `closing` |
| `message` | `WaInboundMessage` |
| `message_ack` | `WaMessageAck` |
| `receipt` | `WaReceipt` |
| `call` | `WaCallEvent` |
| `failure` | `WaFailure` — the server refused the session |
| `logout` | `WaFailure` — the session is over, the device has to pair again |
| `error` | `Error` |

---

## Delivery guarantees

WhatsApp delivers a message over a *pairwise* Signal session — and over a
*group* sender key for group chats. Both can fail in ways the server never
reports: the recipient reinstalled the app, the pre-key expired, a device was
restored from a backup.

### Retries from the peer

A peer that cannot read a message answers with a `<receipt type="retry">`
stanza. Lava answers it automatically:

- The plaintext of the recent messages is kept in a small, bounded cache
  (five minutes, 256 messages) so the answer can be re-encrypted. The
  ciphertext cannot be reused — the peer could not read it in the first place.
- The message is encrypted again for the *device* that asked. For a group
  message the stanza names the device in its `participant` attribute, so only
  that device receives the copy.
- The sender key of a group is remembered per device: a device that already
  knows it does not get the distribution again, and a device that asked for a
  retry gets it with the next message.
- A peer that was never the recipient of the message cannot make the client
  send it again, and the number of attempts per device is capped.

### Retries towards the peer

When a message arrives that Lava cannot decrypt, it asks the server to send
it again with a `<receipt type="retry">` stanza of its own. The counter of
the attempt is raised with every try, and the stanza is only sent a few
times: a message that cannot be decrypted once will not become decryptable by
asking again, and an endless retry loop would keep the server busy.

Both directions are silent by design — nothing has to be enabled, and no
event fires for a message that is only re-sent.

### Group messages

A group message travels twice: once as a *pairwise* payload to every device
that does not know the sender key yet — that is the sender key distribution —
and once as a *group* payload that every member can read with the sender key.

Lava keeps track of which device knows which generation of the sender key, so
the distribution is only sent where it is needed. The bookkeeping survives a
restart.

Two things can go wrong on the way, and both are recoverable:

- A device that never got the distribution cannot read the message and asks
  for a retry. Lava answers the retry and forgets the distribution of that
  device, so the next message carries it again.
- A device that lost the sender key altogether — the member left the group
  and came back, or the app was reinstalled — can be repaired with
  `client.group.redistributeSenderKey(groupJid)`, which sends the
  distribution to every device of the group again.

### When the server refuses the session

The server refuses a session with a `<failure/>` stanza and closes the
socket. Lava reads the stanza and reports it with the `failure` event:

```ts
client.on(LavaClient.FAILURE, ({ reason, location, logout, disconnect }) => {
    // reason:    401, 403, 405, 406, 409, 503 …
    // location:  the server location that reported it
    // logout:    the credentials are worthless, the device has to pair again
    // disconnect: the connection may be re-established
})
```

The reason decides what happens to the session:

| Reason | Meaning | What Lava does |
| --- | --- | --- |
| `401`, `403`, `406` | the session is not authorized, the account is locked or banned | the stored credentials are removed, the `logout` event fires, no reconnect is attempted |
| `405`, `409`, `503` | the client is too old, the build is unknown, the service is down | the credentials stay, the connection is closed and may be re-established |
| anything else | unknown | only the `failure` event fires |

A device whose credentials the server refuses has to pair again, so the
`logout` event is the signal to show a QR code. The credentials are removed
from the store on the way out — a stale session is worth nothing, and
keeping it would only make the next connection fail the same way.

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

const client = new LavaClient({
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
import { MemoryCredentialStore, FileCredentialStore } from 'lava'

new MemoryCredentialStore()            // in-memory, gone on restart
new FileCredentialStore('./lava.json')  // persisted to disk
```

A snapshot contains the Noise identity key pair, the Signal identity key
pair, the signed pre-key, the unused one-time pre-keys and the account's JID.
Implement the `CredentialStore` interface to put it in a database, a
keychain or an encrypted blob.

The snapshot also holds the **app-state store** — the sync keys of the
account and the state of every collection (the version, the digest and the
value MAC of every record). It has to survive a restart, otherwise the device
would ask the server for a fresh snapshot on every connection. The store is
plain JSON, so it costs nothing but a few kilobytes.

The snapshot also holds the **double-ratchet sessions** — the root key, the
chain keys and the ratchet keys of every conversation. This is the one piece
of state that *cannot* be recreated from the key material: the ratchet
advances with every message, so a device that forgets it cannot decrypt the
next message of an established conversation. Lava writes the sessions to the
snapshot as soon as they change, so a restart simply continues the
conversation.

The **sender keys** of the group chats are stored as well. A sender key is
the group counterpart of a double-ratchet session: its chain key advances
with every group message, and the keys received from the other participants
are the only way to decrypt an inbound group message at all.

A participant may **re-key** a group at any time, which starts a new
generation of the sender key. Lava keeps the five most recent generations of
every sender, so a message that was encrypted with a key that has already
been replaced can still be read.

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
- **The app state never reaches the server in the clear**: every record is
  encrypted with a per-device sync key and covered by an HMAC-SHA-512 value
  MAC, and the collection digest (a 128-byte LT-hash) proves that two
  devices hold the same collection without the server reading a single
  record.
- **One-time pre-keys** are consumed exactly once and removed from the pool.

> **Note.** This library is an unofficial client. Use it in accordance with
> WhatsApp's Terms of Service. The authors cannot guarantee that the
> protocol will not change, and using an unofficial client may result in
> your account being banned.

---

## Memory footprint

`npm run bench` measures the resident set size of the library:

```text
Lava memory benchmark
===================================================
baseline (Node + library)    70.87 MB RSS
+ 1 Signal session           73.73 MB RSS
+ full pre-key pool (812)    76.23 MB RSS
===================================================
session cost      2.86 MB
pre-key pool cost 2.50 MB (812 pre-keys, 3.2 KB each)
heap growth       667.8 KB
upload batch      812 pre-keys per upload
ciphertext        152 bytes
schema            532 messages / 2504 fields
```

The library itself adds roughly **3 MB** to a Node.js process, most of which
is the 532-message protobuf schema and the V8 heap churn of the benchmark
itself. A single Signal session costs well under a megabyte of live key
material. (The resident set size moves by a few hundred kilobytes between
runs — the numbers above are one representative run.)

`npm run size` reports the code size:

```text
Lava size report
==============================================
compiled javascript    981.0 KB
type declarations       371.3 KB
typescript sources     1.10 MB

breakdown by module
----------------------------------------------
proto        227.6 KB
transport    191.2 KB
signal       144.9 KB
(root)       131.5 KB
appstate      64.9 KB
protocol      61.8 KB
crypto        40.6 KB
auth          38.2 KB
qr            35.0 KB
media         22.5 KB
message       16.8 KB
util           5.9 KB
----------------------------------------------

runtime dependencies          0
```

---

## Architecture

```text
src/
├── client.ts          the LavaClient orchestrator: lifecycle, routing, dispatch
├── appstate/          the app-state sync: crypto, keys, store, sync client
├── auth/              credentials, the pairing handshake, the SMS registration
├── crypto/            primitives, XEdDSA, the Noise handshake
├── message/           the message codec: padding, secrets, body extraction, cache
├── proto/             the schema-driven protobuf codec (532 messages)
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
npm test            # 440 tests
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

## Notices

Lava is a **clean-room implementation**. No source code, no build output and
no other material was copied from Baileys, Zapo, `whalibmob` or any other
WhatsApp client library. The wire protocol was implemented from the protocol
specification and from observing the traffic of the official clients, and the
naming, the API shape, the code structure and the documentation in this
repository are original work.

The following are trademarks of their respective owners and are used here only
to describe compatibility:

- **WhatsApp** is a trademark of Meta Platforms, Inc.
- **Signal** is a trademark of Signal Messenger, LLC.

This project is not affiliated with, endorsed by, or sponsored by Meta
Platforms, Inc. or Signal Messenger, LLC.

WhatsApp is not affiliated with this project. Using an unofficial client may
violate the WhatsApp Terms of Service and can lead to your account being
banned.

---

## License

MIT
