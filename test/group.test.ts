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

import { parseGroupMetadata, parseGroupParticipants } from '../src/protocol/group.js'
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
