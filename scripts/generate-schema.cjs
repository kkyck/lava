/**
 * Generates `src/proto/schema.ts` from the WhatsApp protobuf definitions.
 *
 * The source is a minified protobufjs static module. Message constructors are
 * assigned as `n.MessageName=function(){...}` at namespace scope, and nested
 * message types are assigned as `e.NestedName=function(){...}` inside their
 * parent's body. This script walks that structure and emits flat TypeScript
 * descriptors with the exact wire field numbers.
 *
 * Run with: node scripts/generate-schema.cjs
 */
const fs = require('node:fs')
const path = require('node:path')

const SRC = '/root/bot-zapo/node_modules/zapo-js/spec/proto/index.js'
const OUT = path.join(__dirname, '..', 'src', 'proto', 'schema.ts')

const src = fs.readFileSync(SRC, 'utf8')

/** Returns the balanced-brace body that starts at or after `start` in `text`. */
function bodyFrom(text, start) {
    const bodyStart = text.indexOf('{', start)
    if (bodyStart === -1) return { body: '', end: text.length }
    let depth = 0
    for (let i = bodyStart; i < text.length; i++) {
        const c = text[i]
        if (c === '{') depth++
        else if (c === '}') {
            depth--
            if (depth === 0) return { body: text.slice(bodyStart + 1, i), end: i + 1 }
        }
    }
    return { body: '', end: text.length }
}

/** Infers the wire type of a field from the encode call that follows it. */
function inferType(after, nestedHint) {
    if (nestedHint) return { type: 'message', nested: nestedHint }
    if (/t\.string\(\)/.test(after)) return { type: 'string' }
    if (/t\.bytes\(\)/.test(after)) return { type: 'bytes' }
    if (/t\.bool\(\)/.test(after)) return { type: 'bool' }
    if (/t\.int32\(\)/.test(after)) return { type: 'int32' }
    if (/t\.int64\(\)/.test(after)) return { type: 'int64' }
    if (/t\.uint64\(\)/.test(after)) return { type: 'uint64' }
    if (/t\.fixed32\(\)/.test(after)) return { type: 'fixed32' }
    if (/t\.fixed64\(\)/.test(after)) return { type: 'fixed64' }
    if (/t\.sfixed32\(\)/.test(after)) return { type: 'sfixed32' }
    if (/t\.sfixed64\(\)/.test(after)) return { type: 'sfixed64' }
    if (/t\.double\(\)/.test(after)) return { type: 'double' }
    if (/t\.float\(\)/.test(after)) return { type: 'float' }
    if (/t\.uint32\(\)/.test(after)) return { type: 'uint32' }
    return { type: 'bytes' }
}

/**
 * Parses the encode function of a message body.
 *
 * protobufjs emits one `if` clause per field:
 *
 * ```js
 * null!=e.username && Object.hasOwnProperty.call(e,"username") && t.uint32(8).uint64(e.username)
 * null!=e.userAgent && Object.hasOwnProperty.call(e,"userAgent") && j.waproto.ClientPayload.UserAgent.encode(e.userAgent,t.uint32(42).fork(),n+1).ldelim()
 * ```
 *
 * The tag passed to `t.uint32(...)` encodes both the field number (tag >> 3)
 * and the wire type (tag & 7).
 *
 * @param body Body of the constructor function (already brace-matched).
 * @param scope Qualified path of the enclosing scope, used to resolve nested
 *   message references that protobufjs emits with a local alias.
 */
function parseFields(body, scope) {
    const encIdx = body.indexOf('.encode=function(e,t,n){')
    if (encIdx === -1) return null
    const enc = bodyFrom(body, encIdx + '.encode=function(e,t,n){'.length - 1).body
    if (!enc.includes('uint32(')) return null

    const fields = new Map()

    // Split the encoder into per-field clauses.
    const clauseRe = /null!=e\.([A-Za-z0-9_$]+)/g
    const starts = []
    let cm
    while ((cm = clauseRe.exec(enc)) !== null) {
        starts.push({ name: cm[1], index: cm.index })
    }

    for (let i = 0; i < starts.length; i++) {
        const clause = starts[i]
        const clauseEnd = i + 1 < starts.length ? starts[i + 1].index : enc.length
        const segment = enc.slice(clause.index, clauseEnd)
        const tagMatch = segment.match(/t\.uint32\((\d+)\)/)
        if (!tagMatch) continue
        const tag = parseInt(tagMatch[1], 10)
        const number = tag >>> 3
        if (number === 0) continue

        let type
        let nested = null
        // Nested messages are encoded through protobufjs' static encoder.
        // The value expression may be indexed (`e.options[o]`) for repeated
        // fields, so the accessor pattern has to allow a trailing index.
        const encodeMatch = segment.match(
            /([A-Za-z0-9_$.]+)\.encode\(e\.[A-Za-z0-9_$]+(?:\[[^\]]*\])?,t\.uint32\(\d+\)/,
        )
        if (encodeMatch) {
            type = 'message'
            nested = resolveNested(encodeMatch[1], scope)
        } else {
            const typeMatch = segment.match(/t\.uint32\(\d+\)\.(\w+)\(/)
            type = typeMatch ? normaliseType(typeMatch[1]) : 'bytes'
        }

        // Repeated fields are encoded via a `length` check plus a loop.
        const repeated = new RegExp(`e\\.${clause.name}\\.length`).test(segment)

        if (!fields.has(number)) {
            fields.set(number, { name: clause.name, type, nested, repeated })
        }
    }

    return fields.size ? fields : null
}

/**
 * Resolves a nested message reference to its qualified path.
 *
 * protobufjs emits two forms:
 * - fully qualified: `j.waproto.CertChain.NoiseCertificate`
 * - scope-local alias: `e.NoiseCertificate` (meaning `<scope>.NoiseCertificate`)
 */
function resolveNested(reference, scope) {
    if (reference.startsWith('j.waproto.')) {
        return reference.slice('j.waproto.'.length)
    }
    // Local alias: `e.<Name>` or `<Name>` inside the current scope.
    const local = reference.split('.').pop()
    return scope ? `${scope}.${local}` : local
}

/** Maps protobufjs writer method names to our field type names. */
function normaliseType(writerMethod) {
    switch (writerMethod) {
        case 'string':
            return 'string'
        case 'bytes':
            return 'bytes'
        case 'bool':
            return 'bool'
        case 'int32':
            return 'int32'
        case 'uint32':
            return 'uint32'
        case 'uint64':
            return 'uint64'
        case 'int64':
            return 'int64'
        case 'sint32':
            return 'sint32'
        case 'sint64':
            return 'sint64'
        case 'fixed32':
            return 'fixed32'
        case 'fixed64':
            return 'fixed64'
        case 'sfixed32':
            return 'sfixed32'
        case 'sfixed64':
            return 'sfixed64'
        case 'float':
            return 'float'
        case 'double':
            return 'double'
        default:
            return 'bytes'
    }
}

/**
 * Collects messages, resolving nested definitions.
 *
 * protobufjs emits nested message types inside the parent constructor as
 * `<parent>.<Nested>=function(){...}()`, where `<parent>` is the minified
 * constructor binding. The nested name is the last segment of that
 * assignment.
 */
const messages = new Map()

/**
 * Finds nested message definitions inside a scope body.
 *
 * @param scopePrefix Qualified path of the enclosing scope.
 * @param scopeBody Body of the enclosing constructor.
 */
function collect(scopePrefix, scopeBody) {
    // Nested definitions appear as `<qualifier>.<Name>=function(){...}()`.
    const defRe = /([A-Za-z0-9_$]+(?:\.[A-Za-z0-9_$]+)*)=function\(\)\{/g
    let m
    const nested = []
    while ((m = defRe.exec(scopeBody)) !== null) {
        const localName = m[1].split('.').pop()
        const { body } = bodyFrom(scopeBody, m.index + m[0].length - 1)
        nested.push({ localName, body })
    }

    for (const def of nested) {
        const fields = parseFields(def.body, scopePrefix)
        const fullName = scopePrefix ? `${scopePrefix}.${def.localName}` : def.localName
        if (fields) {
            // Prefer the richest definition when a name appears twice.
            const existing = messages.get(fullName)
            if (!existing || existing.fields.size < fields.size) {
                messages.set(fullName, { fields })
            }
        }
        // Recurse into the constructor body to find nested message types.
        collect(fullName, def.body)
    }
}

// Top-level namespace: the module assigns messages to `n.` / `j.waproto.`.
const topRe = /(?:^|[;,{(\s])n\.([A-Za-z0-9_$]+)=function\(\)\{/g
let tm
while ((tm = topRe.exec(src)) !== null) {
    const { body } = bodyFrom(src, tm.index + tm[0].length - 1)
    const fields = parseFields(body, tm[1])
    if (fields) messages.set(tm[1], { fields })
    collect(tm[1], body)
}

// ── Select the messages the library needs ───────────────────────────────────
const WANTED = [
    // Transport handshake
    'HandshakeMessage', 'HandshakeMessage.ClientHello', 'HandshakeMessage.ServerHello', 'HandshakeMessage.ClientFinish',
    'CertChain', 'CertChain.NoiseCertificate', 'CertChain.NoiseCertificate.Details',
    // Client payload
    'ClientPayload', 'ClientPayload.UserAgent', 'ClientPayload.WebInfo',
    'ClientPayload.DevicePairingRegistrationData', 'ClientPayload.DNSSource',
    'ClientPayload.UserAgent.AppVersion', 'ClientPayload.WebInfo.WebSubPlatform',
    'ClientPayload.UserAgent.Platform', 'ClientPayload.UserAgent.ReleaseChannel',
    'ClientPayload.ConnectType', 'ClientPayload.ConnectReason',
    'DeviceProps', 'DeviceProps.Version', 'DeviceProps.HistorySyncConfig', 'DeviceProps.PlatformType',
    'WebInfo', 'WebInfo.WebdPayload', 'WebInfo.WebSubPlatform',
    // Messaging
    'Message', 'FutureProofMessage', 'ProtocolMessage', 'ContextInfo', 'MessageContextInfo',
    'DeviceListMetadata', 'MessageKey', 'MessageKeyBundle', 'DeviceSentMessage',
    'ExtendedTextMessage', 'ImageMessage', 'VideoMessage', 'AudioMessage', 'DocumentMessage',
    'StickerMessage', 'ReactionMessage', 'LocationMessage', 'ContactMessage', 'ChatMessage',
    'CallMessage', 'GroupInviteMessage', 'VideoStickerMessage', 'PollCreationMessageV3',
    'PollUpdateMessage', 'ButtonsMessage', 'ButtonsResponseMessage', 'TemplateMessage',
    'InteractiveMessage', 'InteractiveResponseMessage', 'KeepInChatMessage', 'PinInChatMessage',
    'ListMessage', 'ListResponseMessage', 'TemplateButtonReplyMessage', 'ProductMessage',
    'ViewOnceMessage', 'ViewOnceMessageV2', 'EphemeralMessage', 'EphemeralMessage',
    'MessageContextInfo', 'ContextInfo.Expiration', 'ContextInfo.DisappearingMode',
    // Signal
    'SignalMessage', 'PreKeySignalMessage', 'SignalProtocolMessage', 'SignalDeviceList',
    'SignalKeyBundle', 'PreKeyBundle', 'PrimaryKeyBundle', 'UserIdentityKeyBundle',
    'SignalProtocolMessage', 'SignalDeviceList',
    // Signal group (sender key) messages
    'SenderKeyMessage', 'SenderKeyDistributionMessage',
    // Notifications
    'NotificationMessage', 'NotificationMessageInfo', 'WebNotificationsInfo', 'ClientPairingProps',
    'ServerErrorNotification', 'PairSuccessNotification', 'PairErrorNotification', 'PeerDataOperationRequestMessage',
    // App state
    'AppStateSyncKeyShare', 'AppStateSyncKeyRequest', 'HistorySyncNotification',
    'PeerDataOperationRequestMessage', 'PeerDataOperationRequestResponseMessage',
    'PeerDataOperationRequestResponseMessage', 'SyncActionData', 'SyncActionData',
    'InitialSecurityNotificationSettingSync', 'AppStateFatalExceptionNotification',
    'MediaRetryNotification', 'CloudApiThreadControlNotification',
    // App state synchronisation (the `syncd` wire format)
    'SyncdMutation', 'SyncdMutations', 'SyncdRecord', 'SyncdVersion',
    'SyncdSnapshot', 'SyncdPatch', 'ExternalBlobReference', 'KeyId', 'ExitCode',
    // Contacts / groups
    'UserIdentity', 'Contact', 'GroupParticipant', 'GroupInfo',
    'PhotoMessage', 'VideoMessage',
    // Device attestation (ADV)
    'ADVDeviceIdentity', 'ADVSignedDeviceIdentity', 'ADVSignedDeviceIdentityHMAC',
    'ADVKeyIndexList', 'ADVSignedKeyIndexList',
]

/** Normalises a protobufjs name to the flat schema name. */
function flatName(name) {
    return name.replace(/\./g, '_')
}

/** Converts a protobufjs snake_case name to camelCase. */
function camel(name) {
    return name.replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase())
}

const resolved = new Map()
for (const wanted of WANTED) {
    let found = messages.get(wanted)
    let resolvedName = wanted
    if (!found) {
        // Fall back to the last path segment (namespace prefixes vary).
        const tail = wanted.split('.').pop()
        for (const [name, def] of messages) {
            if (name.split('.').pop() === tail && def.fields.size) {
                found = def
                resolvedName = name
                break
            }
        }
    }
    if (found) resolved.set(flatName(resolvedName), found)
}

// ── Transitive closure: include every nested type we reference ──────────────
const byQualified = new Map()
for (const [name, def] of messages) {
    // A bare name may collide across scopes; prefer exact matches.
    byQualified.set(name, { name, def })
}

/** Finds the qualified path of a nested reference. */
function findQualified(reference, parentQualified) {
    if (messages.has(reference)) return reference
    if (parentQualified && messages.has(`${parentQualified}.${reference}`)) {
        return `${parentQualified}.${reference}`
    }
    const tail = reference.split('.').pop()
    for (const name of messages.keys()) {
        if (name.split('.').pop() === tail) return name
    }
    return null
}

const queue = [...resolved.keys()]
const emittedQualified = new Map()
for (const [flat, def] of resolved) {
    const qualified = [...messages.entries()].find(
        ([name, d]) => flatName(name) === flat && d === def,
    )?.[0]
    if (qualified) emittedQualified.set(flat, qualified)
}

while (queue.length) {
    const flat = queue.pop()
    const def = resolved.get(flat)
    if (!def) continue
    const parentQualified = emittedQualified.get(flat)
    for (const field of def.fields.values()) {
        if (field.type !== 'message' || !field.nested) continue
        const qualified = findQualified(field.nested, parentQualified)
        if (!qualified) {
            // The upstream proto contains a few references to message types that
            // are never defined. Treat those fields as opaque bytes so the
            // field number is preserved and the wire format stays valid.
            field.type = 'bytes'
            field.nested = null
            continue
        }
        const nestedFlat = flatName(qualified)
        field.nested = qualified
        if (!resolved.has(nestedFlat)) {
            const nestedDef = messages.get(qualified)
            if (!nestedDef) continue
            resolved.set(nestedFlat, nestedDef)
            emittedQualified.set(nestedFlat, qualified)
            queue.push(nestedFlat)
        }
    }
}

// ── Resolve nested message references to their flat schema names ─────────────
const flatByQualified = new Map()
for (const name of messages.keys()) flatByQualified.set(name, flatName(name))

const lines = []
lines.push('/**')
lines.push(' * WhatsApp protocol buffer schema.')
lines.push(' *')
lines.push(' * Field numbers are extracted from the wire definitions used by the current')
lines.push(' * WhatsApp clients, so the encoding is byte-compatible with the official')
lines.push(' * apps. Only the messages this library actually exchanges are declared,')
lines.push(' * which keeps the runtime footprint small.')
lines.push(' *')
lines.push(' * Generated by `scripts/generate-schema.cjs` - do not edit by hand.')
lines.push(' */')
lines.push('')
// The registry is imported directly: `codec.ts` imports this module to
// populate the registry, so importing it back would create a cycle.
lines.push("import { defineMessage } from './registry.js'")
lines.push('')

for (const [name, def] of resolved) {
    lines.push(`defineMessage('${name}', [`)
    for (const [num, f] of [...def.fields.entries()].sort((a, b) => a[0] - b[0])) {
        const parts = [`number: ${num}`, `name: '${camel(f.name)}'`]
        if (f.type === 'message') {
            parts.push(`type: 'message'`, `message: '${flatName(f.nested || '')}'`)
        } else {
            parts.push(`type: '${f.type}'`)
        }
        if (f.repeated) parts.push('repeated: true')
        lines.push(`    { ${parts.join(', ')} },`)
    }
    lines.push('])')
}

lines.push('')
lines.push('export {}')
lines.push('')

fs.mkdirSync(path.dirname(OUT), { recursive: true })
fs.writeFileSync(OUT, lines.join('\n'))
console.log('emitted:', resolved.size, '/', messages.size, 'known messages')
