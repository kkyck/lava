/**
 * Message codec tests.
 *
 * The codec sits between the protobuf wire format and the library's own
 * object model, so the tests cover the padding, the message secret, the
 * extraction of the encrypted payloads and the user-facing summary.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
    collectGroupCiphertext,
    collectInboundEncryptions,
    decodeMessageBody,
    encodeMessageBody,
    extractSenderKeyDistribution,
    hasMessageContent,
    prepareOutboundPlaintext,
    resolveContentType,
    resolveInboundMessageKey,
    stripInboundPadding,
    summarizeMessageBody,
} from '../src/message/codec.js'
import {
    createUseCaseSecret,
    ensureMessageSecret,
} from '../src/message/secret.js'
import {
    buildReactionContent,
    buildRevokeContent,
    buildTextContent,
} from '../src/protocol/message.js'
import type { BinaryNode } from '../src/transport/binary/types.js'

describe('message body codec', () => {
    it('round-trips a text body', () => {
        const body = buildTextContent('hello world')
        const decoded = decodeMessageBody(encodeMessageBody(body))
        assert.equal(decoded.conversation, 'hello world')
    })

    it('round-trips a nested body', () => {
        const body = buildReactionContent(
            { remoteJid: '123@s.whatsapp.net', fromMe: false, id: 'MSG1' },
            '🔥',
        )
        const decoded = decodeMessageBody(encodeMessageBody(body))
        const reaction = decoded.reactionMessage as Record<string, unknown>
        assert.equal(reaction.text, '🔥')
    })
})

describe('padding', () => {
    it('pads with 1 to 16 bytes', () => {
        for (let i = 0; i < 200; i += 1) {
            const plaintext = prepareOutboundPlaintext({ conversation: 'x' })
            const padLength = plaintext[plaintext.length - 1]!
            assert.ok(padLength >= 1 && padLength <= 16, `bad pad length ${padLength}`)
            assert.equal(
                plaintext.subarray(plaintext.length - padLength).every((b) => b === padLength),
                true,
            )
        }
    })

    it('strips the padding again', () => {
        const body = { conversation: 'round trip' }
        const plaintext = prepareOutboundPlaintext(body)
        const stripped = stripInboundPadding(plaintext)
        const decoded = decodeMessageBody(stripped)
        assert.equal(decoded.conversation, 'round trip')
    })

    it('rejects an empty plaintext', () => {
        assert.throws(() => stripInboundPadding(new Uint8Array(0)), /empty bytes/)
    })

    it('rejects an invalid pad length', () => {
        assert.throws(
            () => stripInboundPadding(new Uint8Array([1, 2, 99])),
            /pad is 99/,
        )
    })
})

describe('message secret', () => {
    it('attaches a 32-byte secret', () => {
        const withSecret = ensureMessageSecret({ conversation: 'hi' })
        const context = withSecret.messageContextInfo as Record<string, unknown>
        const secret = context.messageSecret as Uint8Array
        assert.equal(secret.length, 32)
    })

    it('keeps an existing secret', () => {
        const secret = new Uint8Array(32).fill(9)
        const withSecret = ensureMessageSecret({
            conversation: 'hi',
            messageContextInfo: { messageSecret: secret },
        })
        const context = withSecret.messageContextInfo as Record<string, unknown>
        assert.deepEqual(context.messageSecret, secret)
    })

    it('derives a per-use-case secret', () => {
        const secret = new Uint8Array(32).fill(1)
        const derived = createUseCaseSecret({
            stanzaId: 'MSG1',
            parentMsgOriginalSender: '123@s.whatsapp.net',
            modificationSender: '123@s.whatsapp.net',
            modificationType: 'Enc Reaction',
            messageSecret: secret,
        })
        assert.equal(derived.length, 32)
        // The derivation is deterministic and depends on every input.
        const again = createUseCaseSecret({
            stanzaId: 'MSG1',
            parentMsgOriginalSender: '123@s.whatsapp.net',
            modificationSender: '123@s.whatsapp.net',
            modificationType: 'Enc Reaction',
            messageSecret: secret,
        })
        assert.deepEqual(derived, again)
    })

    it('rejects an empty stanza id', () => {
        assert.throws(() =>
            createUseCaseSecret({
                stanzaId: '',
                parentMsgOriginalSender: 'a',
                modificationSender: 'b',
                modificationType: 'c',
                messageSecret: new Uint8Array(32),
            }),
        )
    })
})

describe('inbound payload collection', () => {
    it('collects the top-level encryption of a direct chat', () => {
        const node: BinaryNode = {
            tag: 'message',
            attrs: { from: '1234567890@s.whatsapp.net', id: 'MSG1' },
            content: [
                {
                    tag: 'enc',
                    attrs: { v: '2', type: 'msg' },
                    content: new Uint8Array([1, 2, 3]),
                },
            ],
        }
        const payloads = collectInboundEncryptions(node)
        assert.equal(payloads.length, 1)
        assert.equal(payloads[0]!.encType, 'msg')
        assert.deepEqual(payloads[0]!.ciphertext, new Uint8Array([1, 2, 3]))
        // A top-level payload is not addressed to a specific device.
        assert.equal(payloads[0]!.deviceJid, undefined)
    })

    it('collects every top-level encryption', () => {
        const node: BinaryNode = {
            tag: 'message',
            attrs: {},
            content: [
                {
                    tag: 'enc',
                    attrs: { v: '2', type: 'pkmsg' },
                    content: new Uint8Array([4, 5]),
                },
                {
                    tag: 'enc',
                    attrs: { v: '2', type: 'msg' },
                    content: new Uint8Array([6]),
                },
            ],
        }
        const payloads = collectInboundEncryptions(node)
        assert.equal(payloads.length, 2)
        assert.equal(payloads[0]!.encType, 'pkmsg')
        assert.equal(payloads[1]!.encType, 'msg')
    })

    it('falls back to the per-device fan-out', () => {
        const node: BinaryNode = {
            tag: 'message',
            attrs: {},
            content: [
                {
                    tag: 'participants',
                    attrs: {},
                    content: [
                        {
                            tag: 'to',
                            attrs: { jid: '123:0@s.whatsapp.net' },
                            content: [
                                {
                                    tag: 'enc',
                                    attrs: { v: '2', type: 'msg' },
                                    content: new Uint8Array([1, 2, 3]),
                                },
                            ],
                        },
                        {
                            tag: 'to',
                            attrs: { jid: '123:1@s.whatsapp.net' },
                            content: [
                                {
                                    tag: 'enc',
                                    attrs: { v: '2', type: 'pkmsg' },
                                    content: new Uint8Array([4, 5]),
                                },
                            ],
                        },
                    ],
                },
            ],
        }
        const payloads = collectInboundEncryptions(node)
        assert.equal(payloads.length, 2)
        assert.equal(payloads[0]!.deviceJid, '123:0@s.whatsapp.net')
        assert.equal(payloads[0]!.encType, 'msg')
        assert.deepEqual(payloads[1]!.ciphertext, new Uint8Array([4, 5]))
        assert.equal(payloads[1]!.deviceJid, '123:1@s.whatsapp.net')
    })

    it('prefers the top-level encryption over the fan-out', () => {
        const node: BinaryNode = {
            tag: 'message',
            attrs: {},
            content: [
                {
                    tag: 'participants',
                    attrs: {},
                    content: [
                        {
                            tag: 'to',
                            attrs: { jid: '123:0@s.whatsapp.net' },
                            content: [
                                {
                                    tag: 'enc',
                                    attrs: { v: '2', type: 'msg' },
                                    content: new Uint8Array([1]),
                                },
                            ],
                        },
                    ],
                },
                {
                    tag: 'enc',
                    attrs: { v: '2', type: 'msg' },
                    content: new Uint8Array([2]),
                },
            ],
        }
        const payloads = collectInboundEncryptions(node)
        assert.equal(payloads.length, 1)
        assert.deepEqual(payloads[0]!.ciphertext, new Uint8Array([2]))
    })

    it('ignores non-binary payloads', () => {
        const node: BinaryNode = {
            tag: 'message',
            attrs: {},
            content: [
                {
                    tag: 'enc',
                    attrs: { v: '2', type: 'msg' },
                    content: [{ tag: 'text', attrs: {}, content: 'not binary' }],
                },
            ],
        }
        assert.equal(collectInboundEncryptions(node).length, 0)
    })

    it('collects the group ciphertext', () => {
        const node: BinaryNode = {
            tag: 'message',
            attrs: {},
            content: [
                {
                    tag: 'enc',
                    attrs: { v: '2', type: 'skmsg' },
                    content: new Uint8Array([9, 9, 9]),
                },
            ],
        }
        const group = collectGroupCiphertext(node)
        assert.ok(group)
        assert.equal(group.encType, 'skmsg')
        assert.deepEqual(group.ciphertext, new Uint8Array([9, 9, 9]))
    })

    it('returns no group ciphertext for a direct message', () => {
        const node: BinaryNode = {
            tag: 'message',
            attrs: {},
            content: [
                {
                    tag: 'enc',
                    attrs: { v: '2', type: 'msg' },
                    content: new Uint8Array([1]),
                },
            ],
        }
        assert.equal(collectGroupCiphertext(node), null)
    })

    it('ignores a fan-out without a sender key', () => {
        const node: BinaryNode = {
            tag: 'message',
            attrs: {},
            content: [
                {
                    tag: 'participants',
                    attrs: {},
                    content: [
                        {
                            tag: 'to',
                            attrs: { jid: '123:0@s.whatsapp.net' },
                            content: [
                                {
                                    tag: 'enc',
                                    attrs: { v: '2', type: 'msg' },
                                    content: new Uint8Array([1]),
                                },
                            ],
                        },
                    ],
                },
            ],
        }
        assert.equal(collectGroupCiphertext(node), null)
    })
})

describe('inbound message key', () => {
    it('resolves a direct-chat key', () => {
        const node: BinaryNode = {
            tag: 'message',
            attrs: {
                from: '1234567890@s.whatsapp.net',
                id: 'MSG1',
                notify: 'Alice',
            },
        }
        const key = resolveInboundMessageKey(
            node,
            '1234567890:3@s.whatsapp.net',
            '9999999999@s.whatsapp.net',
        )
        assert.equal(key.remoteJid, '1234567890@s.whatsapp.net')
        assert.equal(key.id, 'MSG1')
        assert.equal(key.fromMe, false)
        assert.equal(key.isGroup, false)
        assert.equal(key.senderDevice, 3)
        assert.equal(key.pushName, 'Alice')
    })

    it('detects a message sent by this account', () => {
        const node: BinaryNode = {
            tag: 'message',
            attrs: { from: '9999999999@s.whatsapp.net', id: 'MSG2' },
        }
        const key = resolveInboundMessageKey(
            node,
            '9999999999:0@s.whatsapp.net',
            '9999999999@s.whatsapp.net',
        )
        assert.equal(key.fromMe, true)
    })

    it('resolves a group-chat key', () => {
        const node: BinaryNode = {
            tag: 'message',
            attrs: {
                from: '123-456@g.us',
                id: 'MSG3',
                participant: '1234567890:2@s.whatsapp.net',
            },
        }
        const key = resolveInboundMessageKey(
            node,
            '1234567890:2@s.whatsapp.net',
            '9999999999@s.whatsapp.net',
        )
        assert.equal(key.isGroup, true)
        assert.equal(key.participant, '1234567890@s.whatsapp.net')
        assert.equal(key.remoteJid, '123-456@g.us')
    })

    it('detects a broadcast list', () => {
        const node: BinaryNode = {
            tag: 'message',
            attrs: { from: 'status@broadcast', id: 'MSG4' },
        }
        const key = resolveInboundMessageKey(node, undefined, '9999999999@s.whatsapp.net')
        assert.equal(key.isBroadcast, true)
        assert.equal(key.senderDevice, 0)
    })
})

describe('sender key distribution', () => {
    it('extracts a direct distribution message', () => {
        const payload = new Uint8Array([1, 2, 3, 4])
        const body = {
            senderKeyDistributionMessage: {
                groupId: 'group@g.us',
                axolotlSenderKeyDistributionMessage: payload,
            },
        }
        const distribution = extractSenderKeyDistribution(body)
        assert.ok(distribution)
        assert.equal(distribution.groupId, 'group@g.us')
        assert.deepEqual(distribution.payload, payload)
    })

    it('extracts a fast-ratchet distribution message', () => {
        const payload = new Uint8Array([5, 6])
        const body = {
            fastRatchetKeySenderKeyDistributionMessage: {
                groupId: 'group@g.us',
                axolotlSenderKeyDistributionMessage: payload,
            },
        }
        assert.deepEqual(
            extractSenderKeyDistribution(body)?.payload,
            payload,
        )
    })

    it('extracts a nested distribution message', () => {
        const payload = new Uint8Array([7])
        const body = {
            deviceSentMessage: {
                message: {
                    senderKeyDistributionMessage: {
                        groupId: 'group@g.us',
                        axolotlSenderKeyDistributionMessage: payload,
                    },
                },
            },
        }
        assert.deepEqual(extractSenderKeyDistribution(body)?.payload, payload)
    })

    it('returns null when there is none', () => {
        assert.equal(extractSenderKeyDistribution({ conversation: 'hi' }), null)
        assert.equal(
            extractSenderKeyDistribution({
                senderKeyDistributionMessage: { groupId: 'group@g.us' },
            }),
            null,
        )
    })
})

describe('message content', () => {
    it('reports a body that carries a message', () => {
        assert.equal(hasMessageContent({ conversation: 'hi' }), true)
        assert.equal(
            hasMessageContent({
                extendedTextMessage: { text: 'hi' },
            }),
            true,
        )
    })

    it('reports a body that only carries a distribution', () => {
        assert.equal(
            hasMessageContent({
                senderKeyDistributionMessage: {
                    groupId: 'group@g.us',
                    axolotlSenderKeyDistributionMessage: new Uint8Array([1]),
                },
            }),
            false,
        )
    })

    it('ignores the metadata of a message', () => {
        assert.equal(
            hasMessageContent({
                senderKeyDistributionMessage: {
                    groupId: 'group@g.us',
                    axolotlSenderKeyDistributionMessage: new Uint8Array([1]),
                },
                messageContextInfo: { messageSecret: new Uint8Array([2]) },
            }),
            false,
        )
    })

    it('looks inside the envelope of a message', () => {
        assert.equal(
            hasMessageContent({
                deviceSentMessage: {
                    message: {
                        senderKeyDistributionMessage: {
                            groupId: 'group@g.us',
                            axolotlSenderKeyDistributionMessage: new Uint8Array([1]),
                        },
                        messageContextInfo: { messageSecret: new Uint8Array([2]) },
                    },
                },
            }),
            false,
        )
    })
})

describe('message summary', () => {
    it('summarises a plain text', () => {
        const summary = summarizeMessageBody(buildTextContent('hello'))
        assert.equal(summary.type, 'conversation')
        assert.equal(summary.text, 'hello')
    })

    it('summarises a quoted text', () => {
        const body = buildTextContent('reply', {
            quoted: { remoteJid: '123@s.whatsapp.net', fromMe: false, id: 'MSG1' },
        })
        const summary = summarizeMessageBody(body)
        assert.equal(summary.text, 'reply')
        assert.equal(summary.quotedId, 'MSG1')
    })

    it('summarises a reaction', () => {
        const body = buildReactionContent(
            { remoteJid: '123@s.whatsapp.net', fromMe: false, id: 'MSG1' },
            '👍',
        )
        const summary = summarizeMessageBody(body)
        assert.equal(summary.reaction, '👍')
        assert.equal(summary.type, 'reactionMessage')
    })

    it('summarises a revoke', () => {
        const body = buildRevokeContent({
            remoteJid: '123@s.whatsapp.net',
            fromMe: true,
            id: 'MSG1',
        })
        assert.equal(summarizeMessageBody(body).revoked, true)
    })

    it('resolves the content type through the device-sent wrapper', () => {
        const body = { deviceSentMessage: { message: buildTextContent('inner') } }
        assert.equal(resolveContentType(body), 'conversation')
    })
})
