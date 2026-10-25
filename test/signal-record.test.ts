/**
 * Signal record structure tests.
 *
 * The `RecordStructure` and `SenderKeyRecordStructure` blobs are the format
 * every Signal implementation stores its ratchet state in, which makes them
 * the interchange format when a device takes over a conversation that was
 * started somewhere else.
 *
 * The tests therefore decode a record that was produced by another
 * implementation and check that every field survives the trip — and that
 * encoding it again produces the very same bytes.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
    decodeSenderKeyRecord,
    decodeSenderKeyStates,
    decodeSignalSessionRecord,
    encodeSenderKeyRecord,
    encodeSignalSessionRecord,
} from '../src/signal/record.js'
import type { SignalSession } from '../src/signal/session.js'
import type { SenderKeyRecord } from '../src/signal/group.js'
import '../src/proto/schema.js'

/**
 * A `RecordStructure` produced by a different Signal implementation.
 *
 * It holds a session with four receiving chains, a sending chain and a base
 * key — the shape a long-running conversation has.
 */
const FOREIGN_SESSION = Buffer.from(
    'CrEECAMSIQUM1TkQMyV0bM6xzzzATr4T+yyU3wkRzzhTHPC6bWjgUBohBaC8O/tqUK/xhzDmZzxZSLo' +
        '2ZDUntpEujC7xUKUGPBtJIiCLg8IzoGwGCBegHwtt8xcIF8s7lFWmjHAtRbkGPtKUZigAMmsKIQVDGFFanv/QDRxnUd' +
        'KxQ/1WpJfs6d3+vxOLd9WN+8tKXhIg2DGPcVgQmySKJX+sRiHQrDoQqLvx3mjng+R8yBiF/0saJAgAEiCapyaFiLhhn0B5o' +
        'NZNpLnfP8e1ZLpGFzX+Ex6JfcBw/zpJCiEFp1x6JdvHN09zyVH+8RpbU53/1Zd9C/HkqAnA7ff0Mg0aJAgDEiBfwDdNKzFW' +
        'ApEK8c7EgvoriOHLnvyaOd4Vevbo2ckNJjpJCiEFu++dA9W5kX3VuP0XrQJgak/C9TGW/iAFSs1K1OsAJmcaJAgBEiCDHQ1' +
        'IdKiaUti7lF5Hg50mpabyzQi6M2egyxf+ROT0szpJCiEFs1pDcWiQumzcdmo8kbEpWQHAiD1ULPcwaz/FGsnydAwaJAgBE' +
        'iDK4SM5pJp72bImSpGlDKdNFBvTw2f585gx8ufw69z/+jpJCiEFOQTxbSfodvnPTGQ5GbIXSe5/bv65KO5LamPEfwjmRjU' +
        'aJAgDEiBw3EpHhmz5bgfMvK/a09x8tSL8pn9GLqioxHUKVNPUhFDw8v2SB1jVDGohBVU0HYWvKsKbR0tTjmPdsALYYM46EbH' +
        'Mp3ZCUkYTrcJo',
    'base64',
)

/**
 * A `SenderKeyRecordStructure` produced by a different Signal implementation.
 *
 * It holds one sender-key state with a single retained message key.
 */
const FOREIGN_SENDER_KEY = Buffer.from(
    'CokBCPzDq90DEiQIFBIg5u8QVTGAk+9K6c6IZc4Ydm6w51f/9TtCv9B/K+boncAaIwohBdN7n+azmdshQWzcu' +
        'RkRRlNofK4rCH3OhD+a4t/up483IjYIERIyJjRpyrFK3X5rVAI2qC/OIZ+MCmvOG2nwp8WiB67ePbPWIpdjg/LKA' +
        'GiBY1A/jV2VJBQ=',
    'base64',
)

const hex = (value: Uint8Array): string => Buffer.from(value).toString('hex')

describe('signal record structures', () => {
    describe('session records', () => {
        it('decodes a foreign session record', () => {
            const { session, previousSessions } = decodeSignalSessionRecord(
                new Uint8Array(FOREIGN_SESSION),
            )

            assert.equal(session.local.regId, 1621)
            assert.equal(session.remote.regId, 1918859632)
            assert.equal(session.local.pubKey.length, 33)
            assert.equal(session.remote.pubKey.length, 33)
            assert.equal(session.rootKey.length, 32)
            assert.equal(session.aliceBaseKey.length, 33)
            assert.equal(session.prevSendChainHighestIndex, 0)
            assert.equal(session.initialExchangeInfo, null)
            assert.deepEqual(previousSessions, [])
        })

        it('decodes the sending chain', () => {
            const { session } = decodeSignalSessionRecord(new Uint8Array(FOREIGN_SESSION))

            assert.equal(session.sendChain.ratchetKey.pubKey.length, 33)
            assert.equal(session.sendChain.ratchetKey.privKey.length, 32)
            assert.equal(session.sendChain.nextMsgIndex, 0)
            assert.equal(session.sendChain.chainKey.length, 32)
        })

        it('decodes every receiving chain', () => {
            const { session } = decodeSignalSessionRecord(new Uint8Array(FOREIGN_SESSION))

            assert.equal(session.recvChains.length, 4)
            for (const chain of session.recvChains) {
                assert.equal(chain.ratchetPubKey.length, 33)
                assert.equal(chain.chainKey.length, 32)
                assert.deepEqual(chain.unusedMsgKeys, [])
            }
            assert.deepEqual(
                session.recvChains.map((chain) => chain.nextMsgIndex),
                [3, 1, 1, 3],
            )
        })

        it('keeps the private key of the local identity out of the record', () => {
            const privateKey = new Uint8Array(32).fill(7)
            const { session } = decodeSignalSessionRecord(
                new Uint8Array(FOREIGN_SESSION),
                privateKey,
            )

            assert.deepEqual(session.local.privKey, privateKey)
        })

        it('encodes a decoded session back into the same bytes', () => {
            const { session, previousSessions } = decodeSignalSessionRecord(
                new Uint8Array(FOREIGN_SESSION),
            )
            const encoded = encodeSignalSessionRecord(session, previousSessions)

            assert.deepEqual(Buffer.from(encoded), Buffer.from(FOREIGN_SESSION))
        })

        it('round-trips a session with a pending pre-key handshake', () => {
            const session = makeSession()
            const encoded = encodeSignalSessionRecord(session)
            const { session: decoded, previousSessions } = decodeSignalSessionRecord(encoded)

            assert.equal(previousSessions.length, 0)
            assert.equal(decoded.local.regId, session.local.regId)
            assert.equal(decoded.remote.regId, session.remote.regId)
            assert.equal(hex(decoded.rootKey), hex(session.rootKey))
            assert.equal(
                decoded.initialExchangeInfo?.remoteOneTimeId,
                session.initialExchangeInfo?.remoteOneTimeId,
            )
            assert.equal(
                decoded.initialExchangeInfo?.remoteSignedId,
                session.initialExchangeInfo?.remoteSignedId,
            )
            assert.equal(
                hex(decoded.initialExchangeInfo?.localOneTimePubKey ?? new Uint8Array(0)),
                hex(session.initialExchangeInfo?.localOneTimePubKey ?? new Uint8Array(0)),
            )
            assert.equal(
                hex(decoded.sendChain.ratchetKey.privKey),
                hex(session.sendChain.ratchetKey.privKey),
            )
        })

        it('round-trips the previous sessions of a re-key', () => {
            const session = makeSession()
            const previous = makeSession({ rootKey: new Uint8Array(32).fill(3) })
            const encoded = encodeSignalSessionRecord(session, [previous])
            const decoded = decodeSignalSessionRecord(encoded)

            assert.equal(decoded.previousSessions.length, 1)
            assert.equal(hex(decoded.previousSessions[0]!.rootKey), hex(previous.rootKey))
            assert.equal(hex(decoded.session.rootKey), hex(session.rootKey))
        })

        it('keeps the previous sessions on the decoded session', () => {
            const session = makeSession()
            const previous = makeSession({ rootKey: new Uint8Array(32).fill(3) })
            const encoded = encodeSignalSessionRecord(session, [previous])
            const decoded = decodeSignalSessionRecord(encoded)

            // The replaced sessions belong to the session, so a client that
            // only holds the session still has them.
            assert.equal(decoded.session.prevSessions.length, 1)
            assert.equal(
                hex(decoded.session.prevSessions[0]!.rootKey),
                hex(previous.rootKey),
            )
        })

        it('encodes the previous sessions that the session carries', () => {
            const previous = makeSession({ rootKey: new Uint8Array(32).fill(3) })
            const session = makeSession({ prevSessions: [previous] })
            const encoded = encodeSignalSessionRecord(session)
            const decoded = decodeSignalSessionRecord(encoded)

            assert.equal(decoded.previousSessions.length, 1)
            assert.equal(hex(decoded.previousSessions[0]!.rootKey), hex(previous.rootKey))
        })

        it('round-trips the retained message keys of a receiving chain', () => {
            const session = makeSession()
            session.recvChains[0]!.unusedMsgKeys.push({
                index: 4,
                cipherKey: new Uint8Array(32).fill(1),
                macKey: new Uint8Array(32).fill(2),
                iv: new Uint8Array(16).fill(3),
            })
            const encoded = encodeSignalSessionRecord(session)
            const { session: decoded } = decodeSignalSessionRecord(encoded)

            assert.equal(decoded.recvChains[0]!.unusedMsgKeys.length, 1)
            const key = decoded.recvChains[0]!.unusedMsgKeys[0]!
            assert.equal(key.index, 4)
            assert.equal(hex(key.cipherKey), hex(session.recvChains[0]!.unusedMsgKeys[0]!.cipherKey))
            assert.equal(hex(key.macKey), hex(session.recvChains[0]!.unusedMsgKeys[0]!.macKey))
            assert.equal(hex(key.iv), hex(session.recvChains[0]!.unusedMsgKeys[0]!.iv))
        })

        it('rejects a record without a current session', () => {
            assert.throws(
                () => decodeSignalSessionRecord(new Uint8Array([0x08, 0x03])),
                /currentSession/,
            )
        })
    })

    describe('sender key records', () => {
        it('decodes a foreign sender key record', () => {
            const record = decodeSenderKeyRecord(
                new Uint8Array(FOREIGN_SENDER_KEY),
                '120363317298847177@g.us',
                '65138346446989@lid',
            )

            assert.equal(record.groupId, '120363317298847177@g.us')
            assert.equal(record.sender, '65138346446989@lid')
            assert.equal(record.keyId, 1001054716)
            assert.equal(record.iteration, 20)
            assert.equal(record.chainKey.length, 32)
            assert.equal(record.signingPublicKey.length, 33)
            assert.equal(record.signingPrivateKey, undefined)
        })

        it('decodes the retained message keys of a sender key', () => {
            const record = decodeSenderKeyRecord(
                new Uint8Array(FOREIGN_SENDER_KEY),
                '120363317298847177@g.us',
                '65138346446989@lid',
            )

            assert.equal(record.unusedMessageKeys.length, 1)
            assert.equal(record.unusedMessageKeys[0]!.iteration, 17)
            assert.equal(record.unusedMessageKeys[0]!.seed.length, 50)
        })

        it('decodes every state of a sender key record', () => {
            const states = decodeSenderKeyStates(new Uint8Array(FOREIGN_SENDER_KEY))

            assert.equal(states.length, 1)
            assert.equal(states[0]!.keyId, 1001054716)
        })

        it('encodes a decoded sender key back into the same bytes', () => {
            const record = decodeSenderKeyRecord(
                new Uint8Array(FOREIGN_SENDER_KEY),
                '120363317298847177@g.us',
                '65138346446989@lid',
            )
            const encoded = encodeSenderKeyRecord(record)

            assert.deepEqual(Buffer.from(encoded), Buffer.from(FOREIGN_SENDER_KEY))
        })

        it('round-trips a sender key with a private signing key', () => {
            const record: SenderKeyRecord = {
                groupId: 'g',
                sender: 's',
                keyId: 7,
                iteration: 3,
                chainKey: new Uint8Array(32).fill(9),
                signingPublicKey: new Uint8Array(33).fill(1),
                signingPrivateKey: new Uint8Array(32).fill(2),
                unusedMessageKeys: [{ iteration: 2, seed: new Uint8Array(50).fill(3) }],
                previousStates: [],
            }
            const encoded = encodeSenderKeyRecord(record)
            const decoded = decodeSenderKeyRecord(encoded, 'g', 's')

            assert.equal(decoded.keyId, 7)
            assert.equal(decoded.iteration, 3)
            assert.equal(hex(decoded.chainKey), hex(record.chainKey))
            assert.equal(hex(decoded.signingPublicKey), hex(record.signingPublicKey))
            assert.equal(hex(decoded.signingPrivateKey!), hex(record.signingPrivateKey!))
            assert.equal(decoded.unusedMessageKeys.length, 1)
            assert.equal(hex(decoded.unusedMessageKeys[0]!.seed), hex(record.unusedMessageKeys[0]!.seed))
        })

        it('rejects a sender key record without a state', () => {
            assert.throws(
                () => decodeSenderKeyRecord(new Uint8Array([0x08, 0x01]), 'g', 's'),
                /no state/,
            )
        })
    })
})

/** Builds a session for the round-trip tests. */
function makeSession(overrides: Partial<SignalSession> = {}): SignalSession {
    return {
        local: {
            regId: 42,
            pubKey: new Uint8Array(33).fill(1),
            privKey: new Uint8Array(32).fill(2),
        },
        remote: {
            regId: 4242,
            pubKey: new Uint8Array(33).fill(3),
            privKey: new Uint8Array(32).fill(4),
        },
        rootKey: new Uint8Array(32).fill(5),
        recvChains: [
            {
                ratchetPubKey: new Uint8Array(33).fill(6),
                nextMsgIndex: 2,
                chainKey: new Uint8Array(32).fill(7),
                unusedMsgKeys: [],
            },
        ],
        sendChain: {
            ratchetKey: {
                pubKey: new Uint8Array(33).fill(8),
                privKey: new Uint8Array(32).fill(9),
            },
            nextMsgIndex: 1,
            chainKey: new Uint8Array(32).fill(10),
        },
        initialExchangeInfo: {
            remoteOneTimeId: 11,
            remoteSignedId: 12,
            localOneTimePubKey: new Uint8Array(33).fill(13),
        },
        prevSendChainHighestIndex: 5,
        aliceBaseKey: new Uint8Array(33).fill(14),
        prevSessions: [],
        ...overrides,
    }
}
