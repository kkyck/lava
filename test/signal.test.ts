/**
 * Signal protocol tests.
 *
 * The double ratchet is the heart of the library, so the tests cover a full
 * session establishment, message exchange in both directions, pre-key
 * sessions and the sender-key (group) flow.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
    SignalKeyStore,
    generatePreKeyId,
    generatePreKeyPair,
    generateRegistrationInfo,
    generateSignedPreKey,
} from '../src/signal/keys.js'
import { SignalSessionManager } from '../src/signal/manager.js'
import { SenderKeyManager } from '../src/signal/group.js'
import { deserializePreKeyMessage, deserializeSignalMessage } from '../src/signal/session.js'
import { SIGNAL_VERSION } from '../src/signal/constants.js'
import { prependVersion } from '../src/crypto/primitives.js'
import { encode } from '../src/proto/codec.js'
import '../src/proto/schema.js'

const ALICE = '11111111111:0@s.whatsapp.net'
const BOB = '22222222222:0@s.whatsapp.net'
const GROUP = '1234567890-123456@g.us'

/** Builds a key store with a registration, a signed pre-key and one one-time pre-key. */
function makeKeyStore(): SignalKeyStore {
    const store = new SignalKeyStore()
    const registration = generateRegistrationInfo()
    store.setRegistrationInfo(registration)
    store.setSignedPreKey(
        generateSignedPreKey(generatePreKeyId(), registration.identityKeyPair.privKey),
    )
    store.addPreKey(generatePreKeyPair(generatePreKeyId()))
    return store
}

/** Builds a manager that shares a key store with a peer. */
interface Peer {
    store: SignalKeyStore
    manager: SignalSessionManager
}

function makePeer(localAddress: string): Peer {
    const store = makeKeyStore()
    const manager = new SignalSessionManager({
        keyStore: store,
        senderKeyManager: new SenderKeyManager({ localAddress }),
    })
    return { store, manager }
}

/** Starts a pre-key session towards a peer. */
function startSession(
    initiator: Peer,
    target: Peer,
    targetAddress: string,
    initiatorAddress: string,
): void {
    const registration = target.store.getRegistrationInfo()!
    const preKey = target.store.listPreKeys()[0]!
    const signed = target.store.getSignedPreKey()!
    initiator.manager.ensureSession(targetAddress, {
        regId: registration.registrationId,
        identity: registration.identityKeyPair.pubKey,
        signedKey: { id: signed.keyId, publicKey: signed.keyPair.pubKey },
        oneTimeKey: { id: preKey.keyId, publicKey: preKey.keyPair.pubKey },
    })
    void initiatorAddress
}

describe('signal sessions', () => {
    it('establishes a session and exchanges messages', () => {
        const alice = makePeer(ALICE)
        const bob = makePeer(BOB)

        // Alice starts a pre-key session with Bob.
        startSession(alice, bob, BOB, ALICE)

        const encrypted = alice.manager.encryptForDevice(BOB, utf8('hello bob'))
        assert.equal(encrypted.encType, 'pkmsg')

        // Bob decrypts it, which establishes his side of the session.
        const decrypted = bob.manager.decryptFromDevice(ALICE, encrypted.ciphertext, 'pkmsg')
        assert.equal(fromUtf8(decrypted.plaintext), 'hello bob')
        assert.equal(decrypted.sender, ALICE)

        // From now on both sides use the regular "msg" envelope.
        const reply = bob.manager.encryptForDevice(ALICE, utf8('hello alice'))
        assert.equal(reply.encType, 'msg')
        const answer = alice.manager.decryptFromDevice(BOB, reply.ciphertext, 'msg')
        assert.equal(fromUtf8(answer.plaintext), 'hello alice')
    })

    it('sends several messages over one session', () => {
        const alice = makePeer(ALICE)
        const bob = makePeer(BOB)
        startSession(alice, bob, BOB, ALICE)

        const first = alice.manager.encryptForDevice(BOB, utf8('one'))
        bob.manager.decryptFromDevice(ALICE, first.ciphertext, 'pkmsg')

        for (let i = 2; i <= 5; i += 1) {
            const encrypted = alice.manager.encryptForDevice(BOB, utf8(`msg ${i}`))
            assert.equal(encrypted.encType, 'msg')
            const decrypted = bob.manager.decryptFromDevice(ALICE, encrypted.ciphertext, 'msg')
            assert.equal(fromUtf8(decrypted.plaintext), `msg ${i}`)
        }
    })

    it('rejects a tampered ciphertext', () => {
        const alice = makePeer(ALICE)
        const bob = makePeer(BOB)
        startSession(alice, bob, BOB, ALICE)

        const encrypted = alice.manager.encryptForDevice(BOB, utf8('secret'))
        const tampered = new Uint8Array(encrypted.ciphertext)
        tampered[tampered.length - 1] = (tampered[tampered.length - 1]! ^ 0xff)
        assert.throws(() => bob.manager.decryptFromDevice(ALICE, tampered, 'pkmsg'))
    })

    it('consumes the one-time pre-key exactly once', () => {
        const alice = makePeer(ALICE)
        const bob = makePeer(BOB)
        startSession(alice, bob, BOB, ALICE)
        assert.equal(bob.store.getPreKeyCount(), 1)

        const encrypted = alice.manager.encryptForDevice(BOB, utf8('pk'))
        bob.manager.decryptFromDevice(ALICE, encrypted.ciphertext, 'pkmsg')
        assert.equal(bob.store.getPreKeyCount(), 0)
    })

    it('reports the consumed one-time pre-key', () => {
        const alice = makePeer(ALICE)
        const bob = makePeer(BOB)
        startSession(alice, bob, BOB, ALICE)
        const preKeyId = bob.store.listPreKeys()[0]!.keyId

        const consumed: number[] = []
        const observer = new SignalSessionManager({
            keyStore: bob.store,
            onPreKeyConsumed: (id) => consumed.push(id),
        })

        const encrypted = alice.manager.encryptForDevice(BOB, utf8('pk'))
        observer.decryptFromDevice(ALICE, encrypted.ciphertext, 'pkmsg')
        assert.deepEqual(consumed, [preKeyId])
    })

    it('allocates unique pre-key ids that fit the wire format', () => {
        const store = new SignalKeyStore()
        const ids = new Set<number>()
        for (let i = 0; i < 1000; i += 1) {
            const id = store.allocatePreKeyId()
            assert.ok(id > 0 && id <= 0xffffff, `pre-key id ${id} does not fit the wire format`)
            assert.ok(!ids.has(id), `pre-key id ${id} was handed out twice`)
            ids.add(id)
        }
        // The ids are sequential, like the official clients hand them out.
        const sorted = [...ids].sort((a, b) => a - b)
        assert.equal(sorted[0], 1)
        assert.equal(sorted[sorted.length - 1], 1000)
    })

    it('never reuses a pre-key id', () => {
        const store = new SignalKeyStore()
        const first = store.allocatePreKeyId()
        store.addPreKey({ keyId: first, keyPair: generatePreKeyPair(first).keyPair })
        const second = store.allocatePreKeyId()
        assert.notEqual(second, first)
    })

    it('serialises and deserialises a pre-key message', () => {
        const alice = makePeer(ALICE)
        const bob = makePeer(BOB)
        startSession(alice, bob, BOB, ALICE)

        const encrypted = alice.manager.encryptForDevice(BOB, utf8('pk'))
        const parsed = deserializePreKeyMessage(encrypted.ciphertext)
        assert.equal(parsed.localSignedPreKeyId, bob.store.getSignedPreKey()?.keyId)
        assert.ok(parsed.localOneTimeKeyId !== null)
        assert.ok(parsed.remote.pubKey.length > 0)
    })

    it('parses a normal signal message', () => {
        const alice = makePeer(ALICE)
        const bob = makePeer(BOB)
        startSession(alice, bob, BOB, ALICE)

        const encrypted = alice.manager.encryptForDevice(BOB, utf8('pk'))
        bob.manager.decryptFromDevice(ALICE, encrypted.ciphertext, 'pkmsg')

        const reply = bob.manager.encryptForDevice(ALICE, utf8('regular'))
        const parsed = deserializeSignalMessage(reply.ciphertext)
        assert.ok(parsed.counter >= 0)
        assert.ok(parsed.ratchetPubKey.length > 0)
    })

    it('throws when no session exists', () => {
        const alice = makePeer(ALICE)
        assert.throws(() => alice.manager.encryptForDevice(BOB, utf8('x')), /no session/)
    })

    it('decrypts a pre-key message that belongs to an established session', () => {
        const alice = makePeer(ALICE)
        const bob = makePeer(BOB)
        bob.store.addPreKey(generatePreKeyPair(generatePreKeyId()))
        startSession(alice, bob, BOB, ALICE)

        const first = alice.manager.encryptForDevice(BOB, utf8('first'))
        assert.equal(first.encType, 'pkmsg')
        bob.manager.decryptFromDevice(ALICE, first.ciphertext, 'pkmsg')
        const preKeysLeft = bob.store.getPreKeyCount()

        /**
         * A sender keeps the pre-key envelope for every message it produces
         * until it sees a reply, so the receiver gets several pre-key
         * messages that all belong to the same session.
         */
        const second = alice.manager.encryptForDevice(BOB, utf8('second'))
        assert.equal(second.encType, 'msg')
        const wrapped = wrapInPreKeyEnvelope(first.ciphertext, second.ciphertext)

        const out = bob.manager.decryptFromDevice(ALICE, wrapped, 'pkmsg')
        assert.equal(fromUtf8(out.plaintext), 'second')
        // The pre-key of the established session is not consumed a second
        // time, and the session itself is not replaced.
        assert.equal(bob.store.getPreKeyCount(), preKeysLeft)
        assert.equal(bob.manager.sessionCount, 1)
    })

    it('keeps the replaced session when a new session is started', () => {
        const alice = makePeer(ALICE)
        const bob = makePeer(BOB)
        bob.store.addPreKey(generatePreKeyPair(generatePreKeyId()))
        startSession(alice, bob, BOB, ALICE)

        const first = alice.manager.encryptForDevice(BOB, utf8('first'))
        bob.manager.decryptFromDevice(ALICE, first.ciphertext, 'pkmsg')

        // A different peer re-keys the conversation under the same address.
        const second = makePeer(ALICE)
        startSession(second, bob, BOB, ALICE)
        const rekeyed = second.manager.encryptForDevice(BOB, utf8('rekeyed'))
        assert.equal(rekeyed.encType, 'pkmsg')
        bob.manager.decryptFromDevice(ALICE, rekeyed.ciphertext, 'pkmsg')

        // The session that was replaced is kept, so a message that was
        // encrypted with it can still be read.
        const late = alice.manager.encryptForDevice(BOB, utf8('late'))
        assert.equal(late.encType, 'msg')
        const out = bob.manager.decryptFromDevice(ALICE, late.ciphertext, 'msg')
        assert.equal(fromUtf8(out.plaintext), 'late')
    })
})

describe('sender keys (group chats)', () => {
    it('encrypts a group message and shares the sender key', () => {
        const alice = makePeer(ALICE)
        const bob = makePeer(BOB)

        const group = alice.manager.encryptForGroup(GROUP, utf8('group hello'))
        assert.ok(group.ciphertext.length > 0)
        assert.ok(group.distributionMessage)
        assert.equal(group.encType, 'skmsg')

        // Bob receives the distribution message and can then decrypt.
        bob.manager.processSenderKeyDistribution(
            GROUP,
            ALICE,
            group.distributionMessage!,
        )

        const decrypted = bob.manager.decryptFromGroup(GROUP, ALICE, group.ciphertext)
        assert.equal(fromUtf8(decrypted.plaintext), 'group hello')
    })

    it('rejects a group message without a distribution message', () => {
        const bob = makePeer(BOB)
        assert.throws(() => bob.manager.decryptFromGroup(GROUP, ALICE, new Uint8Array([1, 2, 3])))
    })

    it('rejects a tampered group ciphertext', () => {
        const alice = makePeer(ALICE)
        const bob = makePeer(BOB)

        const group = alice.manager.encryptForGroup(GROUP, utf8('group hello'))
        bob.manager.processSenderKeyDistribution(GROUP, ALICE, group.distributionMessage!)

        const tampered = new Uint8Array(group.ciphertext)
        tampered[tampered.length - 1] = (tampered[tampered.length - 1]! ^ 0xff)
        assert.throws(() => bob.manager.decryptFromGroup(GROUP, ALICE, tampered))
    })

    it('finds the sender key of another device of the participant', () => {
        const alice = makePeer(ALICE)
        const bob = makePeer(BOB)

        // The stanza names the participant without its device id, but the
        // sender key belongs to the device that sent the message.
        const aliceSecondDevice = '11111111111:2@s.whatsapp.net'
        const group = alice.manager.encryptForGroup(GROUP, utf8('group hello'))
        bob.manager.processSenderKeyDistribution(GROUP, aliceSecondDevice, group.distributionMessage!)

        const decrypted = bob.manager.decryptFromGroup(GROUP, ALICE, group.ciphertext)
        assert.equal(fromUtf8(decrypted.plaintext), 'group hello')
    })

    it('ignores the sender key of a different participant', () => {
        const alice = makePeer(ALICE)
        const bob = makePeer(BOB)

        const group = alice.manager.encryptForGroup(GROUP, utf8('group hello'))
        bob.manager.processSenderKeyDistribution(GROUP, '33333333333:0@s.whatsapp.net', group.distributionMessage!)

        assert.throws(() => bob.manager.decryptFromGroup(GROUP, ALICE, group.ciphertext))
    })
})

// Small helpers so the test does not depend on the crypto module layout.
function utf8(value: string): Uint8Array {
    return new TextEncoder().encode(value)
}

function fromUtf8(value: Uint8Array): string {
    return new TextDecoder().decode(value)
}

/**
 * Wraps a plain signal message in the pre-key envelope of another one.
 *
 * The envelope of the original message is reused, so both messages carry the
 * same base key and therefore belong to the same session.
 *
 * @param original The pre-key message whose envelope is reused.
 * @param message The plain signal message to wrap.
 */
function wrapInPreKeyEnvelope(original: Uint8Array, message: Uint8Array): Uint8Array {
    const parsed = deserializePreKeyMessage(original)
    const payload = encode('PreKeySignalMessage', {
        registrationId: parsed.remote.regId,
        ...(parsed.localOneTimeKeyId !== null
            ? { preKeyId: parsed.localOneTimeKeyId }
            : {}),
        signedPreKeyId: parsed.localSignedPreKeyId,
        baseKey: parsed.sessionBaseKey,
        identityKey: parsed.remote.pubKey,
        message,
    })
    return prependVersion(payload, SIGNAL_VERSION)
}
