/**
 * Signal session persistence tests.
 *
 * The double-ratchet state is the only part of a Signal session that cannot
 * be recreated from the key material: the root key, the chain keys and the
 * ratchet keys all evolve with every message. A device that forgets them
 * cannot decrypt the next message of an established conversation, so the
 * state has to survive a restart.
 *
 * The tests therefore export the sessions of a running manager, restore them
 * into a fresh manager and continue the conversation.
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
import { deserializeSignalSession } from '../src/signal/persistence.js'

const ALICE = '11111111111:0@s.whatsapp.net'
const BOB = '22222222222:0@s.whatsapp.net'
const GROUP = '1234567890-123456@g.us'
/** The canonical key the sessions are indexed by: `user|server|device`. */
const BOB_KEY = '22222222222|s.whatsapp.net|0'

const utf8 = (value: string): Uint8Array => new TextEncoder().encode(value)
const fromUtf8 = (value: Uint8Array): string => new TextDecoder().decode(value)

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

/** A manager together with the key store it uses. */
interface Peer {
    store: SignalKeyStore
    manager: SignalSessionManager
}

/** Builds a manager that shares a key store with a peer. */
function makePeer(localAddress: string, store: SignalKeyStore = makeKeyStore()): Peer {
    const manager = new SignalSessionManager({
        keyStore: store,
        senderKeyManager: new SenderKeyManager({ localAddress }),
    })
    return { store, manager }
}

/** Starts a pre-key session towards a peer. */
function startSession(initiator: Peer, target: Peer, targetAddress: string): void {
    const registration = target.store.getRegistrationInfo()!
    const preKey = target.store.listPreKeys()[0]!
    const signed = target.store.getSignedPreKey()!
    initiator.manager.ensureSession(targetAddress, {
        regId: registration.registrationId,
        identity: registration.identityKeyPair.pubKey,
        signedKey: { id: signed.keyId, publicKey: signed.keyPair.pubKey },
        oneTimeKey: { id: preKey.keyId, publicKey: preKey.keyPair.pubKey },
    })
}

describe('signal session persistence', () => {
    it('exports the session state of a peer', () => {
        const alice = makePeer(ALICE)
        const bob = makePeer(BOB)
        startSession(alice, bob, BOB)

        const exported = alice.manager.exportSessions()
        assert.equal(Object.keys(exported).length, 1)
        const session = exported[BOB_KEY]
        assert.ok(session)
        // The state is plain JSON, so it survives a snapshot round trip.
        assert.deepEqual(JSON.parse(JSON.stringify(session)), session)
    })

    it('keeps the sending chain alive across a restart', () => {
        const alice = makePeer(ALICE)
        const bob = makePeer(BOB)
        startSession(alice, bob, BOB)

        // The first message establishes the session on Bob's side.
        const first = alice.manager.encryptForDevice(BOB, utf8('one'))
        bob.manager.decryptFromDevice(ALICE, first.ciphertext, 'pkmsg')

        // Alice restarts: the key store is restored, the ratchet state is
        // restored from the snapshot.
        const exported = alice.manager.exportSessions()
        const restarted = makePeer(ALICE, alice.store)
        restarted.manager.importSessions(exported)

        // The chain continues where it left off — Bob can still decrypt.
        const second = restarted.manager.encryptForDevice(BOB, utf8('two'))
        assert.equal(second.encType, 'msg')
        const decrypted = bob.manager.decryptFromDevice(ALICE, second.ciphertext, 'msg')
        assert.equal(fromUtf8(decrypted.plaintext), 'two')
    })

    it('keeps the receiving chain alive across a restart', () => {
        const alice = makePeer(ALICE)
        const bob = makePeer(BOB)
        startSession(alice, bob, BOB)

        const first = alice.manager.encryptForDevice(BOB, utf8('one'))
        bob.manager.decryptFromDevice(ALICE, first.ciphertext, 'pkmsg')

        // Alice restarts and restores her ratchet state.
        const exported = alice.manager.exportSessions()
        const restarted = makePeer(ALICE, alice.store)
        restarted.manager.importSessions(exported)

        // Bob replies; the restored receiving chain still derives the key.
        const reply = bob.manager.encryptForDevice(ALICE, utf8('answer'))
        const decrypted = restarted.manager.decryptFromDevice(BOB, reply.ciphertext, 'msg')
        assert.equal(fromUtf8(decrypted.plaintext), 'answer')
    })

    it('restores a session that is looked up by its address', () => {
        const alice = makePeer(ALICE)
        const bob = makePeer(BOB)
        startSession(alice, bob, BOB)

        const exported = alice.manager.exportSessions()
        const restarted = makePeer(ALICE, alice.store)
        restarted.manager.importSessions(exported)

        assert.equal(restarted.manager.sessionCount, 1)
        assert.ok(restarted.manager.getSession(BOB))
    })

    it('replaces the sessions on import', () => {
        const alice = makePeer(ALICE)
        const bob = makePeer(BOB)
        startSession(alice, bob, BOB)

        const restarted = makePeer(ALICE, alice.store)
        restarted.manager.importSessions(alice.manager.exportSessions())
        assert.equal(restarted.manager.sessionCount, 1)

        // An import without any state clears the sessions again.
        restarted.manager.importSessions(undefined)
        assert.equal(restarted.manager.sessionCount, 0)
    })

    it('reports every change of the ratchet state', () => {
        let changes = 0
        const store = makeKeyStore()
        const manager = new SignalSessionManager({
            keyStore: store,
            onSessionChanged: () => {
                changes += 1
            },
        })
        const bob = makePeer(BOB)
        startSession({ store, manager }, bob, BOB)
        assert.equal(changes, 1)

        manager.encryptForDevice(BOB, utf8('hello'))
        assert.equal(changes, 2)
    })

    it('round-trips a session through JSON', () => {
        const alice = makePeer(ALICE)
        const bob = makePeer(BOB)
        startSession(alice, bob, BOB)
        alice.manager.encryptForDevice(BOB, utf8('one'))

        const exported = alice.manager.exportSessions()
        const json = JSON.stringify(exported)
        const restored = JSON.parse(json) as Record<string, never>
        const session = deserializeSignalSession(restored[BOB_KEY] as never)

        assert.equal(session.rootKey.length, 32)
        assert.equal(session.sendChain.nextMsgIndex, 1)
        assert.equal(session.recvChains.length, 1)
        assert.equal(session.local.pubKey.length, 33)
        assert.equal(session.remote.pubKey.length, 33)
    })
})

describe('sender key persistence', () => {
    it('keeps the received sender key alive across a restart', () => {
        const alice = makePeer(ALICE)
        const bob = makePeer(BOB)

        const group = alice.manager.encryptForGroup(GROUP, utf8('group hello'))
        bob.manager.processSenderKeyDistribution(GROUP, ALICE, group.distributionMessage!)
        bob.manager.decryptFromGroup(GROUP, ALICE, group.ciphertext)

        // Bob restarts: the sender-key state is restored from the snapshot.
        const exported = bob.manager.senderKeyManager.exportState()
        const restarted = makePeer(BOB, bob.store)
        restarted.manager.senderKeyManager.importState(exported)

        // The next message of the group decrypts without a new distribution.
        const next = alice.manager.encryptForGroup(GROUP, utf8('group again'))
        const decrypted = restarted.manager.decryptFromGroup(GROUP, ALICE, next.ciphertext)
        assert.equal(fromUtf8(decrypted.plaintext), 'group again')
    })

    it('keeps the own sender key alive across a restart', () => {
        const alice = makePeer(ALICE)
        alice.manager.encryptForGroup(GROUP, utf8('one'))

        const exported = alice.manager.senderKeyManager.exportState()
        const restarted = makePeer(ALICE, alice.store)
        restarted.manager.senderKeyManager.importState(exported)

        // The restored key continues the chain instead of starting a new one.
        const key = restarted.manager.senderKeyManager.getSenderKey(GROUP)
        assert.ok(key)
        assert.equal(key.iteration, 1)

        const next = restarted.manager.encryptForGroup(GROUP, utf8('two'))
        const record = restarted.manager.senderKeyManager.getSenderKey(GROUP)!
        assert.equal(record.iteration, 2)
        assert.ok(next.distributionMessage)
    })

    it('exports a plain JSON state', () => {
        const alice = makePeer(ALICE)
        alice.manager.encryptForGroup(GROUP, utf8('one'))

        const exported = alice.manager.senderKeyManager.exportState()
        assert.deepEqual(JSON.parse(JSON.stringify(exported)), exported)
        assert.equal(Object.keys(exported.own).length, 1)
        assert.ok(exported.own[GROUP])
    })

    it('clears the state on an empty import', () => {
        const alice = makePeer(ALICE)
        alice.manager.encryptForGroup(GROUP, utf8('one'))

        alice.manager.senderKeyManager.importState(undefined)
        assert.equal(alice.manager.senderKeyManager.getSenderKey(GROUP), undefined)
    })
})
