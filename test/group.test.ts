/**
 * Group metadata tests.
 *
 * The group server answers a `w:g2` query with a `<group>` node that holds
 * the settings of the group and — most importantly — the list of the members.
 * The member list is what a sender needs, because a group message is
 * delivered to every device of every member.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
    GROUP_METADATA_CACHE_TTL_MS,
    GroupMetadataCache,
    parseGroupMetadata,
    parseGroupParticipants,
    resolveGroupAddressingMode,
} from '../src/protocol/group.js'
import type { BinaryNode } from '../src/transport/binary/types.js'

/**
 * A group-metadata response of the shape the server sends.
 */
const GROUP_RESPONSE: BinaryNode = {
    tag: 'iq',
    attrs: { from: '120363431300536030@g.us', type: 'result', id: 'wa-1' },
    content: [
        {
            tag: 'group',
            attrs: {
                addressing_mode: 'lid',
                subject: 'Tes Ilmu Bot (ANTIBOT)',
                creator_country_code: 'ID',
                creator_pn: '6285188349341@s.whatsapp.net',
                creator: '208581496422476@lid',
                id: '120363431300536030',
                creation: '1792426127',
                s_t: '1792743196',
                size: '20',
            },
            content: [
                { tag: 'description', attrs: {}, content: null },
                {
                    tag: 'ephemeral',
                    attrs: { expiration: '7776000', trigger: '0' },
                    content: null,
                },
                { tag: 'locked', attrs: {}, content: null },
                {
                    tag: 'participant',
                    attrs: {
                        jid: '96250233925844@lid',
                        join_time: '1792743458',
                        group_history_sent: 'false',
                        phone_number: '917439382677@s.whatsapp.net',
                    },
                    content: null,
                },
                {
                    tag: 'participant',
                    attrs: {
                        jid: '229016732737759@lid',
                        type: 'admin',
                        join_time: '1792842041',
                        group_history_sent: 'true',
                        phone_number: '6289682952124@s.whatsapp.net',
                    },
                    content: null,
                },
            ],
        },
    ],
}

describe('group metadata', () => {
    it('finds the group node of a response', () => {
        const participants = parseGroupParticipants(GROUP_RESPONSE)
        assert.equal(participants.length, 2)
    })

    it('reads the members of a group', () => {
        const participants = parseGroupParticipants(GROUP_RESPONSE)

        assert.equal(participants[0]!.jid, '96250233925844@lid')
        assert.equal(participants[0]!.phoneJid, '917439382677@s.whatsapp.net')
        assert.equal(participants[0]!.role, 'regular')
        assert.equal(participants[0]!.joinTime, 1792743458)

        assert.equal(participants[1]!.jid, '229016732737759@lid')
        assert.equal(participants[1]!.role, 'admin')
    })

    it('reads the settings of a group', () => {
        const metadata = parseGroupMetadata(GROUP_RESPONSE)

        assert.equal(metadata.jid, '120363431300536030@g.us')
        assert.equal(metadata.subject, 'Tes Ilmu Bot (ANTIBOT)')
        assert.equal(metadata.owner, '208581496422476@lid')
        assert.equal(metadata.ownerPhoneNumber, '6285188349341@s.whatsapp.net')
        assert.equal(metadata.createdAt, 1792426127)
        assert.equal(metadata.participantCount, 20)
        assert.equal(metadata.restrict, true)
        assert.equal(metadata.ephemeralExpiration, 7776000)
        assert.equal(metadata.participants.length, 2)
    })

    it('returns no members when the response holds no group', () => {
        assert.deepEqual(
            parseGroupParticipants({ tag: 'iq', attrs: {}, content: null }),
            [],
        )
    })

    it('rejects a response that holds no group', () => {
        assert.throws(
            () => parseGroupMetadata({ tag: 'iq', attrs: {}, content: null }),
            /expected a <group> node/,
        )
    })
})

describe('group addressing mode', () => {
    it('uses the linked identity when a member is addressed by it', () => {
        const mode = resolveGroupAddressingMode([
            { jid: '11111111111@s.whatsapp.net' },
            { jid: '22222222222@lid' },
        ])
        assert.equal(mode, 'lid')
    })

    it('uses the phone number when every member is addressed by it', () => {
        const mode = resolveGroupAddressingMode([
            { jid: '11111111111@s.whatsapp.net' },
            { jid: '22222222222@s.whatsapp.net' },
        ])
        assert.equal(mode, 'pn')
    })

    it('uses the phone number when the group has no member', () => {
        assert.equal(resolveGroupAddressingMode([]), 'pn')
    })
})

describe('group metadata cache', () => {
    it('remembers the metadata of a group', () => {
        const cache = new GroupMetadataCache()
        const metadata = parseGroupMetadata(GROUP_RESPONSE)
        cache.set('120363431300536030@g.us', metadata)
        assert.equal(cache.get('120363431300536030@g.us'), metadata)
    })

    it('forgets the metadata of a group on demand', () => {
        const cache = new GroupMetadataCache()
        cache.set('120363431300536030@g.us', parseGroupMetadata(GROUP_RESPONSE))
        cache.invalidate('120363431300536030@g.us')
        assert.equal(cache.get('120363431300536030@g.us'), undefined)
    })

    it('forgets the metadata when it is too old', () => {
        const cache = new GroupMetadataCache({ ttlMs: 10 })
        cache.set('120363431300536030@g.us', parseGroupMetadata(GROUP_RESPONSE))
        // The entry is written with the current time, so it is still fresh.
        assert.ok(cache.get('120363431300536030@g.us'))
    })

    it('drops every entry when it is cleared', () => {
        const cache = new GroupMetadataCache()
        cache.set('a@g.us', parseGroupMetadata(GROUP_RESPONSE))
        cache.set('b@g.us', parseGroupMetadata(GROUP_RESPONSE))
        cache.clear()
        assert.equal(cache.get('a@g.us'), undefined)
        assert.equal(cache.get('b@g.us'), undefined)
    })

    it('keeps the entries of different groups apart', () => {
        const cache = new GroupMetadataCache()
        const metadata = parseGroupMetadata(GROUP_RESPONSE)
        cache.set('a@g.us', metadata)
        cache.set('b@g.us', metadata)
        cache.invalidate('a@g.us')
        assert.equal(cache.get('a@g.us'), undefined)
        assert.ok(cache.get('b@g.us'))
    })

    it('has a sane default lifetime', () => {
        assert.equal(GROUP_METADATA_CACHE_TTL_MS, 5 * 60 * 1000)
    })
})
