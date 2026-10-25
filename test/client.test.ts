/**
 * Client integration tests.
 *
 * The client is driven through a mock transport, so the whole pipeline —
 * credentials, pairing, device-list lookup, pre-key fetch, Signal
 * encryption, stanza building and inbound decryption — is exercised without
 * touching the network.
 *
 * The mock transport impersonates a *real* peer device: it owns a Signal
 * identity, a signed pre-key and a one-time pre-key, so the test can
 * decrypt what the client sends and encrypt what the client must receive.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { WaClient } from '../src/client.js'
import { MemoryCredentialStore } from '../src/auth/credentials.js'
import { SignalSessionManager } from '../src/signal/manager.js'
import { SenderKeyManager } from '../src/signal/group.js'
import {
    SignalKeyStore,
    generatePreKeyId,
    generatePreKeyPair,
    generateRegistrationInfo,
    generateSignedPreKey,
} from '../src/signal/keys.js'
import { SIGNAL_UPLOAD_PREKEYS_COUNT } from '../src/signal/api.js'
import {
    decodeMessageBody,
    prepareOutboundPlaintext,
    stripInboundPadding,
} from '../src/message/codec.js'
import { buildTextContent } from '../src/protocol/message.js'
import { findNodeChild, getNodeChildrenByTag } from '../src/transport/node/helpers.js'
import type { BinaryNode } from '../src/transport/binary/types.js'
import type { WaTransport } from '../src/client.js'

const ME_JID = '6281234567890@s.whatsapp.net'
const ME_DEVICE_JID = '6281234567890:0@s.whatsapp.net'
const PEER_JID = '6289999999999@s.whatsapp.net'
const PEER_DEVICE_JID = '6289999999999:0@s.whatsapp.net'

/** A peer device with its own Signal key material. */
interface MockPeer {
    /** The peer's key store. */
    store: SignalKeyStore
    /** The peer's session manager. */
    manager: SignalSessionManager
}

/**
 * Builds a peer device that owns a registration, a signed pre-key and one
 * one-time pre-key — exactly what the server hands out in a key fetch.
 */
function createMockPeer(): MockPeer {
    const store = new SignalKeyStore()
    const registration = generateRegistrationInfo()
    store.setRegistrationInfo(registration)
    store.setSignedPreKey(
        generateSignedPreKey(generatePreKeyId(), registration.identityKeyPair.privKey),
    )
    store.addPreKey(generatePreKeyPair(generatePreKeyId()))
    const manager = new SignalSessionManager({
        keyStore: store,
        senderKeyManager: new SenderKeyManager({ localAddress: PEER_DEVICE_JID }),
    })
    return { store, manager }
}

/** The public key material of a device. */
interface MockKeyMaterial {
    /** The registration id. */
    registrationId: number
    /** The identity public key. */
    identity?: Uint8Array
    /** The signed pre-key id. */
    signedId: number
    /** The signed pre-key. */
    signedKey?: Uint8Array
    /** The signature over the signed pre-key. */
    signature: Uint8Array
    /** The one-time pre-key, when one is available. */
    oneTime?: { id: number; key: Uint8Array }
}

/** A transport that records what the client sends and replays canned IQs. */
class MockTransport implements WaTransport {
    /** Every stanza the client sent. */
    readonly sent: BinaryNode[] = []

    /** The pre-key upload IQs the client sent. */
    readonly uploads: BinaryNode[] = []

    /** The handlers the client registered. */
    handlers: {
        onNode?: (node: BinaryNode) => void
        onClose?: (error?: Error) => void
        onError?: (error: Error) => void
    } = {}

    /** The Noise payload the client handed over. */
    payload: Uint8Array | null = null

    /** The peer device this transport impersonates. */
    readonly peer: MockPeer = createMockPeer()

    /** The error the server answers a signed pre-key rotation with. */
    rotateError: BinaryNode | null = null

    /** The client under test, used to serve its own pre-keys. */
    client: WaClient | null = null

    /** Whether the transport was started. */
    started = false

    /** Whether the transport was closed. */
    closed = false

    async start(): Promise<void> {
        this.started = true
    }

    send(node: BinaryNode): void {
        this.sent.push(node)
    }

    getServerStaticKey(): Uint8Array | null {
        return null
    }

    close(): void {
        this.closed = true
    }

    /** Pushes an inbound stanza to the client. */
    push(node: BinaryNode): void {
        this.handlers.onNode?.(node)
    }

    /** Answers an IQ the way the server would. */
    async query(node: BinaryNode): Promise<BinaryNode> {
        const xmlns = node.attrs.xmlns
        if (xmlns === 'usync') return this.answerDeviceList(node)
        if (xmlns === 'encrypt') {
            const keyFetch = findNodeChild(node, 'key_fetch')
            if (keyFetch) return this.answerKeyFetch(node)
            const digest = findNodeChild(node, 'digest')
            if (digest) return this.answerDigest(node)
            const rotate = findNodeChild(node, 'rotate')
            if (rotate) {
                if (this.rotateError) {
                    const error = this.rotateError
                    this.rotateError = null
                    return error
                }
                return { tag: 'iq', attrs: { id: node.attrs.id ?? '', type: 'result' } }
            }
            this.uploads.push(node)
            return { tag: 'iq', attrs: { id: node.attrs.id ?? '', type: 'result' } }
        }
        return { tag: 'iq', attrs: { id: node.attrs.id ?? '', type: 'result' } }
    }

    /**
     * Answers a key-digest query with a bundle that does not match the
     * client's local state, so the client has to upload a fresh batch.
     */
    private answerDigest(node: BinaryNode): BinaryNode {
        const store = this.client?.signalManager.keyStore
        const registration = store?.getRegistrationInfo()
        const signed = store?.getSignedPreKey()
        if (!registration || !signed) {
            return { tag: 'iq', attrs: { id: node.attrs.id ?? '', type: 'error' } }
        }

        const raw = (key: Uint8Array): Uint8Array =>
            key.length === 33 ? key.subarray(1) : key
        const preKey = store!.listPreKeys(1)[0]

        return {
            tag: 'iq',
            attrs: { id: node.attrs.id ?? '', type: 'result' },
            content: [
                {
                    tag: 'digest',
                    attrs: {},
                    content: [
                        {
                            tag: 'registration',
                            attrs: {},
                            content: intToBytes(4, registration.registrationId),
                        },
                        { tag: 'type', attrs: {}, content: new Uint8Array([5]) },
                        {
                            tag: 'identity',
                            attrs: {},
                            content: raw(registration.identityKeyPair.pubKey),
                        },
                        {
                            tag: 'skey',
                            attrs: {},
                            content: [
                                {
                                    tag: 'id',
                                    attrs: {},
                                    content: intToBytes(3, signed.keyId),
                                },
                                {
                                    tag: 'value',
                                    attrs: {},
                                    content: raw(signed.keyPair.pubKey),
                                },
                                {
                                    tag: 'signature',
                                    attrs: {},
                                    content: signed.signature,
                                },
                            ],
                        },
                        {
                            tag: 'list',
                            attrs: {},
                            content: preKey
                                ? [
                                      {
                                          tag: 'key',
                                          attrs: {},
                                          content: intToBytes(3, preKey.keyId),
                                      },
                                  ]
                                : [],
                        },
                        // A deliberately wrong hash: the client has to notice
                        // the drift and upload a fresh batch.
                        { tag: 'hash', attrs: {}, content: new Uint8Array(20) },
                    ],
                },
            ],
        }
    }

    /** Answers a device-list query. */
    private answerDeviceList(node: BinaryNode): BinaryNode {
        const usync = findNodeChild(node, 'usync')
        const list = usync ? findNodeChild(usync, 'list') : undefined
        const jids = list
            ? getNodeChildrenByTag(list, 'user').map((user) => user.attrs.jid ?? '')
            : []

        return {
            tag: 'iq',
            attrs: { id: node.attrs.id ?? '', type: 'result' },
            content: [
                {
                    tag: 'usync',
                    attrs: {},
                    content: [
                        {
                            tag: 'list',
                            attrs: {},
                            content: jids.map((jid) => ({
                                tag: 'user',
                                attrs: { jid },
                                content: [
                                    {
                                        tag: 'devices',
                                        attrs: {},
                                        content: [
                                            {
                                                tag: 'device-list',
                                                attrs: {},
                                                content: [{ tag: 'device', attrs: { id: '0' } }],
                                            },
                                        ],
                                    },
                                ],
                            })),
                        },
                    ],
                },
            ],
        }
    }

    /** Answers a pre-key fetch with the public key material of the target. */
    private answerKeyFetch(node: BinaryNode): BinaryNode {
        const keyFetch = findNodeChild(node, 'key_fetch')
        const users = keyFetch ? getNodeChildrenByTag(keyFetch, 'user') : []

        return {
            tag: 'iq',
            attrs: { id: node.attrs.id ?? '', type: 'result' },
            content: [
                {
                    tag: 'list',
                    attrs: {},
                    content: users.map((user) => ({
                        tag: 'user',
                        attrs: { jid: user.attrs.jid ?? '' },
                        content: [this.buildDeviceNode(user.attrs.jid ?? '')],
                    })),
                },
            ],
        }
    }

    /**
     * Builds the `<device>` entry of a key-fetch answer.
     *
     * @param jid The user the bundle belongs to.
     */
    private buildDeviceNode(jid: string): BinaryNode {
        const material =
            jid === ME_JID ? this.clientMaterial() : this.peerMaterial()
        return {
            tag: 'device',
            attrs: { id: '0' },
            content: [
                {
                    tag: 'registration',
                    attrs: {},
                    content: intToBytes(4, material.registrationId),
                },
                {
                    tag: 'identity',
                    attrs: {},
                    content: rawKey(material.identity),
                },
                {
                    tag: 'skey',
                    attrs: {},
                    content: [
                        {
                            tag: 'id',
                            attrs: {},
                            content: intToBytes(3, material.signedId),
                        },
                        {
                            tag: 'value',
                            attrs: {},
                            content: rawKey(material.signedKey),
                        },
                        {
                            tag: 'signature',
                            attrs: {},
                            content: material.signature,
                        },
                    ],
                },
                ...(material.oneTime
                    ? [
                          {
                              tag: 'key',
                              attrs: {},
                              content: [
                                  {
                                      tag: 'id',
                                      attrs: {},
                                      content: intToBytes(3, material.oneTime.id),
                                  },
                                  {
                                      tag: 'value',
                                      attrs: {},
                                      content: rawKey(material.oneTime.key),
                                  },
                              ],
                          },
                      ]
                    : []),
            ],
        }
    }

    /** The public key material of the peer device. */
    private peerMaterial(): MockKeyMaterial {
        const registration = this.peer.store.getRegistrationInfo()
        const signed = this.peer.store.getSignedPreKey()
        const oneTime = this.peer.store.listPreKeys()[0]
        return {
            registrationId: registration?.registrationId ?? 0,
            identity: registration?.identityKeyPair.pubKey,
            signedId: signed?.keyId ?? 0,
            signedKey: signed?.keyPair.pubKey,
            signature: signed?.signature ?? new Uint8Array(64),
            oneTime: oneTime
                ? { id: oneTime.keyId, key: oneTime.keyPair.pubKey }
                : undefined,
        }
    }

    /** The public key material of the client under test. */
    private clientMaterial(): MockKeyMaterial {
        const store = this.client?.signalManager.keyStore
        const registration = store?.getRegistrationInfo()
        const signed = store?.getSignedPreKey()
        const oneTime = store?.listPreKeys()[0]
        return {
            registrationId: registration?.registrationId ?? 0,
            identity: registration?.identityKeyPair.pubKey,
            signedId: signed?.keyId ?? 0,
            signedKey: signed?.keyPair.pubKey,
            signature: signed?.signature ?? new Uint8Array(64),
            oneTime: oneTime ? { id: oneTime.keyId, key: oneTime.keyPair.pubKey } : undefined,
        }
    }
}

/**
 * Strips the `0x05` prefix of a serialized key.
 *
 * The wire format carries the raw 32-byte public key, while the library
 * keeps the serialized 33-byte form internally.
 */
function rawKey(key: Uint8Array | undefined): Uint8Array {
    if (!key) return new Uint8Array(32)
    return key.length === 33 ? key.subarray(1) : key
}

/** Encodes a number the way the protocol expects it. */
function intToBytes(length: number, value: number): Uint8Array {
    const out = new Uint8Array(length)
    let remaining = value
    for (let i = length - 1; i >= 0; i -= 1) {
        out[i] = remaining & 0xff
        remaining = Math.floor(remaining / 256)
    }
    return out
}

/** Builds a client wired to a mock transport. */
function makeClient(
    mode: 'mobile' | 'web' = 'mobile',
): { client: WaClient; transport: MockTransport } {
    const transport = new MockTransport()
    const client = new WaClient({
        transport: mode,
        credentials: new MemoryCredentialStore(),
        transportFactory: (context) => {
            transport.handlers = context.handlers
            transport.payload = context.noise.payload
            return transport
        },
    })
    transport.client = client
    return { client, transport }
}

/** Waits for a condition to become true. */
async function waitFor(condition: () => boolean, timeoutMs = 2000): Promise<void> {
    const deadline = Date.now() + timeoutMs
    while (!condition()) {
        if (Date.now() > deadline) throw new Error('timed out waiting for the condition')
        await new Promise((resolve) => setTimeout(resolve, 5))
    }
}

describe('client lifecycle', () => {
    it('starts the transport and reports the state', async () => {
        const { client, transport } = makeClient()
        const states: string[] = []
        client.on(WaClient.CONNECTION, ({ state }: { state: string }) => states.push(state))

        await client.connect()
        assert.ok(transport.started)
        assert.equal(client.getState(), 'pairing')
        assert.ok(states.includes('connecting'))

        await client.disconnect()
        assert.ok(transport.closed)
        assert.equal(client.getState(), 'disconnected')
    })

    it('creates credentials on the first connect', async () => {
        const store = new MemoryCredentialStore()
        const transport = new MockTransport()
        const client = new WaClient({
            credentials: store,
            transportFactory: () => transport,
        })
        await client.connect()

        const snapshot = await store.load()
        assert.ok(snapshot)
        assert.ok(snapshot.noiseKeyPair.pub.length > 0)
        assert.ok(snapshot.identityKeyPair.pub.length > 0)
        assert.ok(snapshot.signedPreKey.id > 0)
        assert.equal(snapshot.preKeys.length, SIGNAL_UPLOAD_PREKEYS_COUNT)
    })

    it('reuses the stored credentials', async () => {
        const store = new MemoryCredentialStore()
        const first = new MockTransport()
        const clientA = new WaClient({ credentials: store, transportFactory: () => first })
        await clientA.connect()
        const snapshotA = await store.load()

        const second = new MockTransport()
        const clientB = new WaClient({ credentials: store, transportFactory: () => second })
        await clientB.connect()
        const snapshotB = await store.load()

        assert.equal(snapshotA?.noiseKeyPair.pub, snapshotB?.noiseKeyPair.pub)
    })

    it('sends a registration payload before pairing and a login payload after', async () => {
        const { client, transport } = makeClient()
        await client.connect()
        // Before pairing, the payload carries the Signal identity.
        assert.ok(transport.payload)
        assert.ok(transport.payload.length > 0)

        transport.push({
            tag: 'success',
            attrs: {},
            content: [
                {
                    tag: 'props',
                    attrs: { jid: ME_JID, lid: '12345@lid', pushname: 'Tester' },
                },
            ],
        })
        await waitFor(() => client.getState() === 'connected')
        assert.equal(client.getMeJid(), ME_JID)
        assert.equal(client.getSession().paired, true)
    })

    it('emits auth_paired once the server confirms the identity', async () => {
        const { client, transport } = makeClient()
        await client.connect()

        let paired: { meJid?: string; meLid?: string } | null = null
        client.on(WaClient.AUTH_PAIRED, (event: { meJid?: string }) => {
            paired = event
        })

        transport.push({
            tag: 'success',
            attrs: {},
            content: [{ tag: 'props', attrs: { jid: ME_JID, lid: '999@lid' } }],
        })

        await waitFor(() => paired !== null)
        assert.equal(paired!.meJid, ME_JID)
    })
})

describe('client pre-keys', () => {
    /** Connects a client and marks it as paired. */
    async function pairedClient(): Promise<{ client: WaClient; transport: MockTransport }> {
        const pair = makeClient()
        await pair.client.connect()
        pair.transport.push({
            tag: 'success',
            attrs: {},
            content: [{ tag: 'props', attrs: { jid: ME_JID } }],
        })
        await waitFor(() => pair.client.getState() === 'connected')
        await waitFor(() => pair.transport.uploads.length > 0)
        return pair
    }

    it('hands out pre-key ids that fit the three byte wire field', async () => {
        const { client } = await pairedClient()
        const store = client.signalManager.keyStore
        const signed = store.getSignedPreKey()
        assert.ok(signed)
        assert.ok(signed.keyId > 0 && signed.keyId <= 0xffffff)

        const ids = store.listPreKeys().map((record) => record.keyId)
        assert.ok(ids.length > 0)
        for (const id of ids) {
            assert.ok(id > 0 && id <= 0xffffff, `pre-key id ${id} does not fit the wire format`)
        }
    })

    it('hands out unique, sequential pre-key ids', async () => {
        const { client } = await pairedClient()
        const ids = client.signalManager.keyStore.listPreKeys().map((record) => record.keyId)
        assert.equal(new Set(ids).size, ids.length)
        const sorted = [...ids].sort((a, b) => a - b)
        for (let i = 1; i < sorted.length; i += 1) {
            assert.equal(sorted[i]! - sorted[i - 1]!, 1, 'the pre-key ids are not sequential')
        }
    })

    it('uploads the pre-keys and keeps them for the inbound handshake', async () => {
        const { client, transport } = await pairedClient()
        const snapshot = await client.getSession()
        assert.ok(snapshot.paired)

        // The upload happened…
        assert.equal(transport.uploads.length, 1)
        const upload = transport.uploads[0]!
        const list = findNodeChild(upload, 'list')
        assert.ok(list)
        assert.equal(getNodeChildrenByTag(list, 'key').length, SIGNAL_UPLOAD_PREKEYS_COUNT)

        // …but the pre-keys stay in the store: the server keeps handing them
        // out, and the device must be able to decrypt the messages that use
        // them.
        assert.equal(
            client.signalManager.keyStore.getPreKeyCount(),
            SIGNAL_UPLOAD_PREKEYS_COUNT,
        )
    })

    it('moves the upload cursor forward so a pre-key is never uploaded twice', async () => {
        const { client, transport } = await pairedClient()
        assert.equal(transport.uploads.length, 1)

        // A second connect must not upload the same pre-keys again.
        await client.disconnect()
        await client.connect()
        await new Promise((resolve) => setTimeout(resolve, 50))
        assert.equal(transport.uploads.length, 1)
    })

    it('does not upload again while the server still holds a batch', async () => {
        const { client, transport } = await pairedClient()
        assert.equal(transport.uploads.length, 1)

        // The peer consumes one of the client's one-time pre-keys. The server
        // still holds the rest of the batch, so nothing is uploaded.
        transport.push(buildInboundPreKeyMessage(transport))
        await waitFor(
            () => client.signalManager.keyStore.getPreKeyCount() === SIGNAL_UPLOAD_PREKEYS_COUNT - 1,
        )

        await client.disconnect()
        await client.connect()
        await new Promise((resolve) => setTimeout(resolve, 50))
        assert.equal(transport.uploads.length, 1)
    })

    it('uploads a fresh batch when the server reports a low pre-key count', async () => {
        const { client, transport } = await pairedClient()
        assert.equal(transport.uploads.length, 1)

        // The server tells the client that its pool of our pre-keys runs
        // low with an `<notification type="encrypt"><count/></notification>`.
        transport.push({
            tag: 'notification',
            attrs: { id: 'notif-1', type: 'encrypt', from: 's.whatsapp.net' },
            content: [{ tag: 'count', attrs: { value: '10' } }],
        })

        await waitFor(() => transport.uploads.length > 1)

        // The notification is acknowledged…
        const ack = transport.sent.find((node) => node.tag === 'ack')
        assert.ok(ack)
        assert.equal(ack!.attrs.class, 'notification')
        assert.equal(ack!.attrs.type, 'encrypt')
        assert.equal(ack!.attrs.id, 'notif-1')

        // …and a full fresh batch is uploaded.
        const uploaded = getNodeChildrenByTag(
            findNodeChild(transport.uploads[1]!, 'list')!,
            'key',
        )
        assert.equal(uploaded.length, SIGNAL_UPLOAD_PREKEYS_COUNT)

        // The server holds a batch again.
        assert.equal(client.signalManager.keyStore.getServerHasPreKeys(), true)
    })

    it('repairs a drifted key bundle when the server asks for a digest', async () => {
        const { client, transport } = await pairedClient()
        assert.equal(transport.uploads.length, 1)

        // The server asks the client to validate its key bundle.
        transport.push({
            tag: 'notification',
            attrs: { id: 'notif-2', type: 'encrypt', from: 's.whatsapp.net' },
            content: [{ tag: 'digest', attrs: {} }],
        })

        // The digest does not match the local state, so a fresh batch is
        // uploaded.
        await waitFor(() => transport.uploads.length > 1)

        const uploaded = getNodeChildrenByTag(
            findNodeChild(transport.uploads[1]!, 'list')!,
            'key',
        )
        assert.equal(uploaded.length, SIGNAL_UPLOAD_PREKEYS_COUNT)
        assert.equal(client.signalManager.keyStore.getServerHasPreKeys(), true)
    })

    it('remembers that the server holds a batch of pre-keys', async () => {
        const store = new MemoryCredentialStore()
        const transport = new MockTransport()
        const client = new WaClient({
            credentials: store,
            transportFactory: (context) => {
                transport.handlers = context.handlers
                transport.payload = context.noise.payload
                return transport
            },
        })
        transport.client = client
        await client.connect()
        transport.push({
            tag: 'success',
            attrs: {},
            content: [{ tag: 'props', attrs: { jid: ME_JID } }],
        })
        await waitFor(() => client.getState() === 'connected')
        await waitFor(() => transport.uploads.length > 0)

        const snapshot = await store.load()
        assert.equal(snapshot?.serverHasPreKeys, true)
        assert.equal(
            snapshot?.firstUnuploadedPreKeyId,
            SIGNAL_UPLOAD_PREKEYS_COUNT + 1,
        )
    })

    it('validates the key bundle when the server rejects a signed pre-key', async () => {
        const { client, transport } = await pairedClient()
        const uploadsBefore = transport.uploads.length

        // The server rejects the rotated signed pre-key with a `409`.
        transport.rotateError = {
            tag: 'iq',
            attrs: { id: 'rotate-1', type: 'error' },
            content: [
                { tag: 'error', attrs: { code: '409', text: 'conflict' } },
            ],
        }
        await client.rotateSignedPreKey()

        // The key bundle is validated against the server's digest, and the
        // drift is repaired with a fresh batch.
        await waitFor(() => transport.uploads.length > uploadsBefore)
        assert.equal(client.signalManager.keyStore.getServerHasPreKeys(), true)
    })


    it('consumes a one-time pre-key and drops it from the snapshot', async () => {
        const { client, transport } = await pairedClient()
        const store = client.signalManager.keyStore
        const before = store.getPreKeyCount()

        // The peer starts a session towards the client, which consumes one
        // of the client's one-time pre-keys.
        const inbound = buildInboundPreKeyMessage(transport)
        let received: { text?: string } | null = null
        client.on(WaClient.MESSAGE, (event: { text?: string }) => {
            received = event
        })
        transport.push(inbound)
        await waitFor(() => received !== null)

        assert.equal(received!.text, 'peer hello')
        assert.equal(store.getPreKeyCount(), before - 1)
    })
})

describe('client messaging', () => {
    /** Connects a client and marks it as paired. */
    async function pairedClient(): Promise<{ client: WaClient; transport: MockTransport }> {
        const pair = makeClient()
        await pair.client.connect()
        pair.transport.push({
            tag: 'success',
            attrs: {},
            content: [{ tag: 'props', attrs: { jid: ME_JID } }],
        })
        await waitFor(() => pair.client.getState() === 'connected')
        return pair
    }

    it('sends a text message with a per-device payload', async () => {
        const { client, transport } = await pairedClient()

        const id = await client.message.send(PEER_JID, 'hello world')
        assert.ok(id.length > 0)

        const stanza = transport.sent.find((node) => node.tag === 'message')
        assert.ok(stanza)
        assert.equal(stanza.attrs.to, PEER_JID)
        assert.equal(stanza.attrs.id, id)
        assert.equal(stanza.attrs.type, 'text')

        const participants = findNodeChild(stanza, 'participants')
        assert.ok(participants)
        const tos = getNodeChildrenByTag(participants, 'to')
        assert.equal(tos.length, 1)
        // Device 0 is addressed without a device suffix.
        assert.equal(tos[0]!.attrs.jid, PEER_JID)
        const enc = findNodeChild(tos[0]!, 'enc')
        assert.ok(enc)
        assert.ok(enc.content instanceof Uint8Array)
        assert.ok(enc.content.length > 0)
    })

    it('uses the mobile message id format', async () => {
        const { client } = await pairedClient()
        const id = await client.message.send(PEER_JID, 'hi')
        // The mobile format is 32 hex characters starting with `ac`.
        assert.equal(id.length, 32)
        assert.ok(id.startsWith('AC'))
    })

    it('uses the web message id format on the web transport', async () => {
        const { client, transport } = makeClient('web')
        await client.connect()
        transport.push({
            tag: 'success',
            attrs: {},
            content: [{ tag: 'props', attrs: { jid: ME_JID } }],
        })
        await waitFor(() => client.getState() === 'connected')

        const id = await client.message.send(PEER_JID, 'hi')
        assert.equal(id.length, 22)
        assert.ok(id.startsWith('3EB0'))
    })

    it('encrypts the first message as a pre-key message the peer can read', async () => {
        const { client, transport } = await pairedClient()

        await client.message.send(PEER_JID, 'first')

        const stanza = transport.sent.find((node) => node.tag === 'message')
        assert.ok(stanza)
        const enc = findNodeChild(getNodeChildrenByTag(findNodeChild(stanza, 'participants')!, 'to')[0]!, 'enc')
        assert.ok(enc)
        // The very first message of a session is a pre-key message.
        assert.equal(enc.attrs.type, 'pkmsg')

        // The peer completes the handshake and reads the plaintext.
        const decrypted = transport.peer.manager.decryptFromDevice(
            ME_DEVICE_JID,
            enc.content as Uint8Array,
            'pkmsg',
        )
        const body = decodeMessageBody(stripInboundPadding(decrypted.plaintext))
        assert.equal(body.conversation, 'first')
        assert.equal(decrypted.sender, ME_DEVICE_JID)
    })

    it('decrypts an inbound message and emits it', async () => {
        const { client, transport } = await pairedClient()

        // Send a message so the client learns the peer's key bundle and
        // establishes the Signal session.
        await client.message.send(PEER_JID, 'first')

        const snapshot = client.getSession()
        assert.equal(snapshot.meJid, ME_JID)

        const inbound = buildInboundMessage(transport)

        let received: { text?: string; jid?: string } | null = null
        client.on(WaClient.MESSAGE, (event: { text?: string; jid?: string }) => {
            received = event
        })
        transport.push(inbound)
        await waitFor(() => received !== null)

        assert.equal(received!.text, 'inbound hello')
        assert.equal(received!.jid, PEER_JID)
    })

    it('acknowledges an inbound message', async () => {
        const { client, transport } = await pairedClient()
        await client.message.send(PEER_JID, 'first')

        const inbound = buildInboundMessage(transport)
        transport.push(inbound)
        await waitFor(() => transport.sent.some((node) => node.tag === 'ack'))

        const ack = transport.sent.find((node) => node.tag === 'ack')
        assert.ok(ack)
        assert.equal(ack.attrs.class, 'message')
    })

    it('sends a read receipt', async () => {
        const { client, transport } = await pairedClient()
        await client.message.read(PEER_JID, { id: 'MSG1' })
        const receipt = transport.sent.find((node) => node.tag === 'receipt')
        assert.ok(receipt)
        assert.equal(receipt.attrs.type, 'read')
        assert.equal(receipt.attrs.id, 'MSG1')
    })

    it('sends a presence update', async () => {
        const { client, transport } = await pairedClient()
        client.presence.available('Tester')
        const presence = transport.sent.find((node) => node.tag === 'presence')
        assert.ok(presence)
        assert.equal(presence.attrs.type, 'available')
    })

    it('sends a chat state', async () => {
        const { client, transport } = await pairedClient()
        client.presence.chatState(PEER_JID, 'composing')
        const state = transport.sent.find((node) => node.tag === 'chatstate')
        assert.ok(state)
        assert.equal(state.attrs.to, PEER_JID)
        assert.equal(state.content, 'composing')
    })

    it('places a call', async () => {
        const { client, transport } = await pairedClient()
        const callId = await client.call.offer(PEER_JID, { video: true })
        assert.ok(callId.length > 0)

        const call = transport.sent.find((node) => node.tag === 'call')
        assert.ok(call)
        assert.equal(call.attrs.to, PEER_JID)
        assert.equal(call.attrs['call-id'], callId)
        assert.equal(call.attrs['call-creator'], ME_JID)
        const offer = findNodeChild(call, 'offer')
        assert.ok(offer)
        assert.equal(offer.attrs['call-id'], callId)
        // A video call carries a `<video/>` marker.
        const video = findNodeChild(offer, 'video')
        assert.ok(video)
    })
})

/**
 * Builds an inbound `<message>` stanza the client can decrypt.
 *
 * The peer first completes the handshake with the client's first message and
 * then answers with a regular `msg` envelope, which the official clients
 * deliver as a **top-level** `<enc>` child.
 */
function buildInboundMessage(transport: MockTransport): BinaryNode {
    // The client's first message established the pre-key session; the peer
    // consumes it and answers inside the same ratchet.
    const outbound = transport.sent.find((node) => node.tag === 'message')
    assert.ok(outbound, 'the client did not send a message')
    const participants = findNodeChild(outbound, 'participants')
    assert.ok(participants)
    const tos = getNodeChildrenByTag(participants, 'to')
    assert.ok(tos.length > 0)
    const enc = findNodeChild(tos[0]!, 'enc')
    assert.ok(enc)
    assert.ok(enc.content instanceof Uint8Array)

    // The peer completes the handshake with the pre-key message.
    transport.peer.manager.decryptFromDevice(ME_DEVICE_JID, enc.content, 'pkmsg')

    // ... and answers with a normal message.
    const plaintext = prepareOutboundPlaintext(buildTextContent('inbound hello'))
    const reply = transport.peer.manager.encryptForDevice(ME_DEVICE_JID, plaintext)
    assert.equal(reply.encType, 'msg')

    return {
        tag: 'message',
        attrs: {
            from: PEER_JID,
            id: 'INBOUND1',
            type: 'text',
            notify: 'Peer',
            t: '1700000000',
        },
        content: [
            {
                tag: 'enc',
                attrs: { v: '2', type: reply.encType },
                content: reply.ciphertext,
            },
        ],
    }
}

/**
 * Builds an inbound `<message>` stanza that starts a *new* session.
 *
 * The peer fetches the client's pre-key bundle — the mock transport serves
 * the client's own public keys — establishes a session towards the client and
 * sends a `pkmsg`, which makes the client consume one of its one-time
 * pre-keys.
 */
function buildInboundPreKeyMessage(transport: MockTransport): BinaryNode {
    const client = transport.client
    assert.ok(client, 'the transport does not know the client')

    const store = client.signalManager.keyStore
    const registration = store.getRegistrationInfo()
    const signed = store.getSignedPreKey()
    const oneTime = store.listPreKeys()[0]
    assert.ok(registration && signed && oneTime)

    // The peer establishes a session towards the client using the client's
    // published pre-key bundle.
    transport.peer.manager.ensureSession(ME_DEVICE_JID, {
        regId: registration.registrationId,
        identity: registration.identityKeyPair.pubKey,
        signedKey: { id: signed.keyId, publicKey: signed.keyPair.pubKey },
        oneTimeKey: { id: oneTime.keyId, publicKey: oneTime.keyPair.pubKey },
    })

    const plaintext = prepareOutboundPlaintext(buildTextContent('peer hello'))
    const encrypted = transport.peer.manager.encryptForDevice(ME_DEVICE_JID, plaintext)
    assert.equal(encrypted.encType, 'pkmsg')

    return {
        tag: 'message',
        attrs: {
            from: PEER_JID,
            id: 'INBOUND2',
            type: 'text',
            notify: 'Peer',
            t: '1700000001',
        },
        content: [
            {
                tag: 'enc',
                attrs: { v: '2', type: encrypted.encType },
                content: encrypted.ciphertext,
            },
        ],
    }
}
