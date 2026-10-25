/**
 * Node builder tests.
 *
 * The builders produce the exact stanzas the official client sends, so the
 * tests pin down the attribute names and the nesting.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
    buildAckNode,
    buildIqErrorNode,
    buildIqResultNode,
    buildNotificationAckNode,
    buildReceiptNode,
    buildRetryReceiptNode,
} from '../src/transport/node/builders/global.js'
import {
    WA_COMPANION_PLATFORM_ID,
    WA_SIGNALING,
    buildCompanionFinishRequestNode,
    buildCompanionHelloRequestNode,
    buildGetCountryCodeRequestNode,
    buildPairDeviceSignResultNode,
} from '../src/transport/node/builders/pairing.js'
import {
    buildDirectMessageFanoutNode,
    buildGroupSenderKeyMessageNode,
} from '../src/transport/node/builders/message.js'
import { findNodeChild, getNodeChildrenByTag } from '../src/transport/node/helpers.js'
import { buildMissingPreKeysFetchIq } from '../src/signal/api.js'
import type { BinaryNode } from '../src/transport/binary/types.js'

describe('global node builders', () => {
    it('builds a message acknowledgement', () => {
        const node = buildAckNode('MSGID', '123@s.whatsapp.net', { type: 'text' })
        assert.equal(node.tag, 'ack')
        assert.equal(node.attrs.id, 'MSGID')
        assert.equal(node.attrs.to, '123@s.whatsapp.net')
        assert.equal(node.attrs.class, 'message')
        assert.equal(node.attrs.type, 'text')
    })

    it('adds the participant to a group acknowledgement', () => {
        const node = buildAckNode('MSGID', 'group@g.us', {
            type: 'text',
            participant: '123@s.whatsapp.net',
        })
        assert.equal(node.attrs.participant, '123@s.whatsapp.net')
    })

    it('builds a notification acknowledgement', () => {
        const node = buildNotificationAckNode('NID', 's.whatsapp.net', 'w:gp2')
        assert.equal(node.tag, 'ack')
        assert.equal(node.attrs.class, 'notification')
        assert.equal(node.attrs.type, 'w:gp2')
        assert.equal(node.attrs.id, 'NID')
    })

    it('builds a receipt', () => {
        const node = buildReceiptNode('MSGID', '123@s.whatsapp.net', 'read', {
            participant: '456@s.whatsapp.net',
        })
        assert.equal(node.tag, 'receipt')
        assert.equal(node.attrs.id, 'MSGID')
        assert.equal(node.attrs.type, 'read')
        assert.equal(node.attrs.participant, '456@s.whatsapp.net')
    })

    it('builds a retry receipt', () => {
        const node = buildRetryReceiptNode('MSGID', '123@s.whatsapp.net', 2)
        assert.equal(node.tag, 'receipt')
        assert.equal(node.attrs.type, 'retry')
        const retry = findNodeChild(node, 'retry')
        assert.ok(retry)
        assert.equal(retry.attrs.count, '2')
        assert.equal(retry.attrs.id, 'MSGID')
    })

    it('answers an IQ with a result', () => {
        const request: BinaryNode = {
            tag: 'iq',
            attrs: { id: 'IQ1', from: 's.whatsapp.net', type: 'get', xmlns: 'usync' },
        }
        const result = buildIqResultNode(request)
        assert.equal(result.tag, 'iq')
        assert.equal(result.attrs.id, 'IQ1')
        assert.equal(result.attrs.type, 'result')
        assert.equal(result.attrs.to, 's.whatsapp.net')
    })

    it('answers an IQ with an error', () => {
        const request: BinaryNode = {
            tag: 'iq',
            attrs: { id: 'IQ1', from: 's.whatsapp.net', type: 'get' },
        }
        const error = buildIqErrorNode(request, { code: 404, text: 'not found' })
        assert.equal(error.attrs.type, 'error')
        const detail = findNodeChild(error, 'error')
        assert.ok(detail)
        assert.equal(detail.attrs.code, '404')
        assert.equal(detail.attrs.text, 'not found')
    })
})

describe('pairing node builders', () => {
    it('builds the companion hello IQ', () => {
        const node = buildCompanionHelloRequestNode({
            phoneJid: '6281234567890@s.whatsapp.net',
            wrappedCompanionEphemeralPub: new Uint8Array([1, 2, 3]),
            companionServerAuthKeyPub: new Uint8Array([4, 5, 6]),
            companionPlatformId: WA_COMPANION_PLATFORM_ID.ANDROID,
            companionPlatformDisplay: 'Pixel 8 Pro',
        })
        assert.equal(node.tag, 'iq')
        assert.equal(node.attrs.xmlns, 'md')
        assert.equal(node.attrs.type, 'set')

        const reg = findNodeChild(node, 'link_code_companion_reg')
        assert.ok(reg)
        assert.equal(reg.attrs.jid, '6281234567890@s.whatsapp.net')
        assert.equal(reg.attrs.stage, WA_SIGNALING.LINK_CODE_STAGE_COMPANION_HELLO)
        assert.equal(reg.attrs.should_show_push_notification, 'false')

        const wrapped = findNodeChild(reg, 'link_code_pairing_wrapped_companion_ephemeral_pub')
        assert.ok(wrapped)
        assert.ok(wrapped.content instanceof Uint8Array)
        assert.deepEqual(wrapped.content, new Uint8Array([1, 2, 3]))
    })

    it('builds the country code IQ', () => {
        const node = buildGetCountryCodeRequestNode()
        assert.equal(node.attrs.xmlns, 'md')
        assert.equal(node.attrs.type, 'get')
        const reg = findNodeChild(node, 'link_code_companion_reg')
        assert.ok(reg)
        assert.equal(reg.attrs.stage, WA_SIGNALING.LINK_CODE_STAGE_GET_COUNTRY_CODE)
    })

    it('builds the companion finish IQ', () => {
        const node = buildCompanionFinishRequestNode({
            phoneJid: '6281234567890@s.whatsapp.net',
            wrappedKeyBundle: new Uint8Array([9, 9]),
            companionIdentityPublic: new Uint8Array([8, 8]),
            ref: 'REF123',
        })
        const reg = findNodeChild(node, 'link_code_companion_reg')
        assert.ok(reg)
        assert.equal(reg.attrs.stage, WA_SIGNALING.LINK_CODE_STAGE_COMPANION_FINISH)
        const ref = findNodeChild(reg, 'link_code_pairing_ref')
        assert.ok(ref)
        assert.equal(ref.content, 'REF123')
    })

    it('builds the pair-device sign result', () => {
        const node = buildPairDeviceSignResultNode(new Uint8Array([7, 7]), 3)
        assert.equal(node.attrs.type, 'result')
        const sign = findNodeChild(node, 'pair-device-sign')
        assert.ok(sign)
        const identity = findNodeChild(sign, 'device-identity')
        assert.ok(identity)
        assert.equal(identity.attrs['key-index'], '3')
    })
})

describe('signal node builders', () => {
    it('always sends the registration id of a pre-key request', () => {
        // The server silently ignores a `key_fetch` request whose device node
        // has no `<registration>` element: it never answers, so the request
        // times out. Zero is the "unknown" marker.
        const node = buildMissingPreKeysFetchIq([
            { userJid: '123@s.whatsapp.net', devices: [{ deviceId: 3 }] },
        ])
        assert.equal(node.attrs.xmlns, 'encrypt')
        assert.equal(node.attrs.type, 'get')

        const keyFetch = findNodeChild(node, 'key_fetch')
        assert.ok(keyFetch)
        const users = getNodeChildrenByTag(keyFetch, 'user')
        assert.equal(users.length, 1)
        assert.equal(users[0]!.attrs.jid, '123@s.whatsapp.net')

        const devices = getNodeChildrenByTag(users[0]!, 'device')
        assert.equal(devices.length, 1)
        assert.equal(devices[0]!.attrs.id, '3')

        const registration = findNodeChild(devices[0]!, 'registration')
        assert.ok(registration, 'the registration element must never be missing')
        assert.deepEqual(
            Array.from(registration.content as Uint8Array),
            [0, 0, 0, 0],
        )
    })

    it('sends the known registration id', () => {
        const node = buildMissingPreKeysFetchIq([
            {
                userJid: '123@s.whatsapp.net',
                devices: [{ deviceId: 0, registrationId: 1621 }],
            },
        ])
        const keyFetch = findNodeChild(node, 'key_fetch')
        assert.ok(keyFetch)
        const users = getNodeChildrenByTag(keyFetch, 'user')
        const devices = getNodeChildrenByTag(users[0]!, 'device')
        const registration = findNodeChild(devices[0]!, 'registration')
        assert.ok(registration)
        assert.deepEqual(Array.from(registration.content as Uint8Array), [0, 0, 6, 85])
    })
})

describe('message node builders', () => {
    it('builds a direct fan-out message', () => {
        const node = buildDirectMessageFanoutNode(
            { to: '123@s.whatsapp.net', type: 'text', id: 'MSG1' },
            [
                { jid: '123:0@s.whatsapp.net', encType: 'msg', ciphertext: new Uint8Array([1]) },
                { jid: '123:1@s.whatsapp.net', encType: 'pkmsg', ciphertext: new Uint8Array([2]) },
            ],
        )
        assert.equal(node.tag, 'message')
        assert.equal(node.attrs.to, '123@s.whatsapp.net')
        assert.equal(node.attrs.id, 'MSG1')

        const participants = findNodeChild(node, 'participants')
        assert.ok(participants)
        const tos = getNodeChildrenByTag(participants, 'to')
        assert.equal(tos.length, 2)
        assert.equal(tos[0]!.attrs.jid, '123:0@s.whatsapp.net')
        const enc = findNodeChild(tos[0]!, 'enc')
        assert.ok(enc)
        assert.equal(enc.attrs.v, '2')
        assert.equal(enc.attrs.type, 'msg')
    })

    it('builds a group sender-key message', () => {
        const node = buildGroupSenderKeyMessageNode(
            { to: 'group@g.us', type: 'text', id: 'MSG2', phash: '2:abcdef' },
            [{ jid: '123:0@s.whatsapp.net', encType: 'pkmsg', ciphertext: new Uint8Array([3]) }],
            new Uint8Array([4, 5, 6]),
        )
        assert.equal(node.tag, 'message')
        assert.equal(node.attrs.to, 'group@g.us')
        assert.equal(node.attrs.phash, '2:abcdef')

        const enc = findNodeChild(node, 'enc')
        assert.ok(enc)
        assert.equal(enc.attrs.type, 'skmsg')
        assert.ok(enc.content instanceof Uint8Array)
        assert.deepEqual(enc.content, new Uint8Array([4, 5, 6]))
    })
})
