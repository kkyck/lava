/**
 * JID and message-protocol tests.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
    buildDeviceJid,
    getLoginIdentity,
    isBroadcastJid,
    isGroupJid,
    isLidJid,
    isUserJid,
    normalizeRecipientJid,
    parsePhoneJid,
    splitJid,
    toUserJid,
} from '../src/protocol/jid.js'
import {
    buildContactContent,
    buildLocationContent,
    buildPollContent,
    buildReactionContent,
    buildRevokeContent,
    buildTextContent,
    getContentType,
    resolveOutboundMessageAttrs,
    unwrapMessage,
} from '../src/protocol/message.js'
import { computePhashV2 } from '../src/protocol/phash.js'

describe('jid helpers', () => {
    it('splits a jid', () => {
        assert.deepEqual(splitJid('1234567890@s.whatsapp.net'), {
            user: '1234567890',
            server: 's.whatsapp.net',
        })
    })

    it('strips the device suffix', () => {
        assert.equal(toUserJid('1234567890:5@s.whatsapp.net'), '1234567890@s.whatsapp.net')
        assert.equal(toUserJid('1234567890@s.whatsapp.net'), '1234567890@s.whatsapp.net')
    })

    it('recognises the jid kinds', () => {
        assert.ok(isGroupJid('123-456@g.us'))
        assert.ok(isBroadcastJid('status@broadcast'))
        assert.ok(isLidJid('123456789@lid'))
        assert.ok(isUserJid('1234567890@s.whatsapp.net'))
        assert.ok(!isUserJid('123-456@g.us'))
    })

    it('builds a device jid', () => {
        assert.equal(
            buildDeviceJid('1234567890', 's.whatsapp.net', 3),
            '1234567890:3@s.whatsapp.net',
        )
        assert.equal(buildDeviceJid('1234567890', 's.whatsapp.net', 0), '1234567890@s.whatsapp.net')
    })

    it('parses a phone number', () => {
        assert.equal(parsePhoneJid('6281234567890'), '6281234567890@s.whatsapp.net')
        assert.equal(parsePhoneJid('+62 812-3456-7890'), '6281234567890@s.whatsapp.net')
        assert.equal(parsePhoneJid('081234567890@c.us'), '081234567890@s.whatsapp.net')
    })

    it('extracts the login identity', () => {
        assert.deepEqual(getLoginIdentity('6281234567890:12@s.whatsapp.net'), {
            username: 6281234567890,
            device: 12,
        })
    })

    it('normalises a recipient', () => {
        // A bare phone number becomes a phone-number JID.
        assert.equal(normalizeRecipientJid('+6281234567890'), '6281234567890@s.whatsapp.net')
        // A group id is recognised by its dash.
        assert.equal(normalizeRecipientJid('123-456'), '123-456@g.us')
        // An explicit JID is passed through unchanged.
        assert.equal(
            normalizeRecipientJid('6281234567890@s.whatsapp.net'),
            '6281234567890@s.whatsapp.net',
        )
        assert.throws(() => normalizeRecipientJid(''))
    })
})

describe('message content', () => {
    it('builds a text message', () => {
        const body = buildTextContent('hello')
        assert.equal(body.conversation, 'hello')
        assert.equal(getContentType(body), 'conversation')
    })

    it('builds a quoted text message', () => {
        const body = buildTextContent('reply', {
            quoted: { remoteJid: '123@s.whatsapp.net', fromMe: false, id: 'MSG1' },
        })
        const extended = body.extendedTextMessage as Record<string, unknown>
        const context = extended.contextInfo as Record<string, unknown>
        const quoted = context.quotedMessage as Record<string, unknown>
        const key = quoted.key as Record<string, unknown>
        assert.equal(key.id, 'MSG1')
        assert.equal(getContentType(body), 'extendedTextMessage')
    })

    it('builds a reaction', () => {
        const body = buildReactionContent(
            { remoteJid: '123@s.whatsapp.net', fromMe: false, id: 'MSG1' },
            '👍',
        )
        const reaction = body.reactionMessage as Record<string, unknown>
        assert.equal(reaction.text, '👍')
        assert.equal(getContentType(body), 'reactionMessage')
    })

    it('builds a revoke', () => {
        const body = buildRevokeContent({
            remoteJid: '123@s.whatsapp.net',
            fromMe: true,
            id: 'MSG1',
        })
        const protocol = body.protocolMessage as Record<string, unknown>
        assert.equal(protocol.type, 0)
    })

    it('builds a location', () => {
        const body = buildLocationContent({ latitude: 1.5, longitude: 2.5, name: 'Office' })
        const location = body.locationMessage as Record<string, unknown>
        assert.equal(location.degreesLatitude, 1.5)
        assert.equal(location.name, 'Office')
    })

    it('builds a contact', () => {
        const body = buildContactContent({ displayName: 'Alice', vcard: 'BEGIN:VCARD' })
        const contact = body.contactMessage as Record<string, unknown>
        assert.equal(contact.displayName, 'Alice')
    })

    it('builds a poll and rejects an empty one', () => {
        const body = buildPollContent({
            name: 'Lunch?',
            options: [{ name: 'Pizza' }, { name: 'Sushi' }],
        })
        assert.equal(getContentType(body), 'pollCreationMessageV3')
        assert.throws(() => buildPollContent({ name: 'x', options: [] }))
    })

    it('derives the outbound attributes', () => {
        const attrs = resolveOutboundMessageAttrs(buildTextContent('hi'))
        assert.equal(attrs.typeAttr, 'text')
    })

    it('unwraps a device-sent message', () => {
        const inner = buildTextContent('inner')
        const wrapped = { deviceSentMessage: { message: inner } }
        assert.equal(getContentType(unwrapMessage(wrapped)), 'conversation')
    })
})

describe('phash', () => {
    it('produces a version-2 hash', () => {
        const hash = computePhashV2([
            '11111111111:0@s.whatsapp.net',
            '22222222222:0@s.whatsapp.net',
        ])
        assert.ok(hash.startsWith('2:'))
    })

    it('is independent of the participant order', () => {
        const a = computePhashV2(['111:0@s.whatsapp.net', '222:0@s.whatsapp.net'])
        const b = computePhashV2(['222:0@s.whatsapp.net', '111:0@s.whatsapp.net'])
        assert.equal(a, b)
    })

    it('changes when the participant set changes', () => {
        const a = computePhashV2(['111:0@s.whatsapp.net'])
        const b = computePhashV2(['111:0@s.whatsapp.net', '222:0@s.whatsapp.net'])
        assert.notEqual(a, b)
    })
})
