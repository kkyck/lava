// Validates src/proto/schema.ts against an independent parse of the wire
// definitions in the reference protobufjs module.
//
// Run: node scripts/validate-schema.cjs
const fs = require('node:fs')
const path = require('node:path')

const SRC = '/root/bot-zapo/node_modules/zapo-js/spec/proto/index.js'
const SCHEMA = path.join(__dirname, '..', 'src', 'proto', 'schema.ts')

const src = fs.readFileSync(SRC, 'utf8')
const schemaSrc = fs.readFileSync(SCHEMA, 'utf8')

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

// ── Independently parse every message's field numbers ───────────────────────
const truth = new Map()

const defRe = /([A-Za-z0-9_$]+(?:\.[A-Za-z0-9_$]+)*)=function\(\)\{/g
let m
const topLevel = []
while ((m = defRe.exec(src)) !== null) {
    const { body } = bodyFrom(src, m.index + m[0].length - 1)
    topLevel.push({ path: m[1], body })
}

/** Extracts `field -> { name, wire }` from an encoder body. */
function extract(enc) {
    const fields = new Map()
    const clauseRe = /null!=e\.([A-Za-z0-9_$]+)/g
    const starts = []
    let cm
    while ((cm = clauseRe.exec(enc)) !== null) starts.push({ name: cm[1], index: cm.index })
    for (let i = 0; i < starts.length; i++) {
        const seg = enc.slice(starts[i].index, i + 1 < starts.length ? starts[i + 1].index : enc.length)
        const tag = seg.match(/t\.uint32\((\d+)\)/)
        if (!tag) continue
        const rawTag = parseInt(tag[1], 10)
        const number = rawTag >>> 3
        if (number === 0) continue
        if (!fields.has(number)) fields.set(number, { name: starts[i].name, wire: rawTag & 7 })
    }
    return fields
}

/** Walks a constructor body for its own encoder. */
function encoderOf(body) {
    const idx = body.indexOf('.encode=function(e,t,n){')
    if (idx === -1) return null
    const enc = bodyFrom(body, idx + '.encode=function(e,t,n){'.length - 1).body
    return enc.includes('uint32(') ? enc : null
}

function walk(scopePath, body) {
    const enc = encoderOf(body)
    if (enc) {
        const fields = extract(enc)
        if (fields.size) truth.set(scopePath, fields)
    }
    const nestedRe = /([A-Za-z0-9_$]+(?:\.[A-Za-z0-9_$]+)*)=function\(\)\{/g
    let nm
    while ((nm = nestedRe.exec(body)) !== null) {
        const local = nm[1].split('.').pop()
        const { body: nestedBody } = bodyFrom(body, nm.index + nm[0].length - 1)
        walk(`${scopePath}.${local}`, nestedBody)
    }
}

// Top-level namespace members are assigned as `n.<Name>=function(){...}()`.
const nsRe = /n\.([A-Za-z0-9_$]+)=function\(\)\{/g
while ((m = nsRe.exec(src)) !== null) {
    const { body } = bodyFrom(src, m.index + m[0].length - 1)
    walk(m[1], body)
}

// ── Parse the generated schema ──────────────────────────────────────────────

/**
 * Maps our field types onto their protobuf wire class.
 *
 * `2` (length-delimited) covers strings, bytes and nested messages, so the
 * comparison catches the difference between a `bytes` field and a `message`
 * field only when the reference reports a nested-message encoder.
 */
function wireClass(type) {
    switch (type) {
        case 'string':
        case 'bytes':
        case 'message':
            return 2
        case 'int32':
        case 'int64':
        case 'uint32':
        case 'uint64':
        case 'bool':
            return 0
        case 'fixed64':
        case 'sfixed64':
        case 'double':
            return 1
        case 'fixed32':
        case 'sfixed32':
        case 'float':
            return 5
        default:
            return -1
    }
}

const generated = new Map()
const genRe = /^defineMessage\('([^']+)', \[([\s\S]*?)^\]\)/gm
while ((m = genRe.exec(schemaSrc)) !== null) {
    const fields = new Map()
    for (const line of m[2].split('\n')) {
        const f = line.match(/number: (\d+), name: '([^']+)'.*?type: '([^']+)'/)
        if (f) fields.set(+f[1], { name: f[2], type: f[3] })
    }
    generated.set(m[1], fields)
}

// ── Compare ─────────────────────────────────────────────────────────────────
const flat = (s) => s.replace(/\./g, '_')
const truthByFlat = new Map()
for (const [name, fields] of truth) truthByFlat.set(flat(name), fields)

let checked = 0
let mismatches = 0
const problems = []

for (const [name, fields] of generated) {
    const reference = truthByFlat.get(name)
    if (!reference) {
        problems.push(`${name}: no ground truth found`)
        continue
    }
    for (const [number, field] of fields) {
        const expected = reference.get(number)
        if (!expected) {
            problems.push(`${name}.${field.name} (#${number}): unknown field number in reference`)
            mismatches++
            continue
        }
        checked++
        if (expected.name !== field.name) {
            problems.push(
                `${name} #${number}: generated "${field.name}" but reference says "${expected.name}"`,
            )
            mismatches++
            continue
        }
        // A `message` field must be encoded as a nested message (wire type 2),
        // and so must `string`/`bytes`. The distinguishing check is that a
        // `message` field may never be emitted as a scalar.
        const generatedWire = wireClass(field.type)
        if (generatedWire !== expected.wire) {
            problems.push(
                `${name}.${field.name} (#${number}): wire type ${generatedWire} does not match reference ${expected.wire}`,
            )
            mismatches++
        }
    }
    // Detect fields present in the reference but missing from the schema.
    for (const [number, expected] of reference) {
        if (!fields.has(number)) {
            problems.push(
                `${name} #${number} (${expected.name}): missing from generated schema`,
            )
            mismatches++
        }
    }
}

console.log(`generated messages: ${generated.size}`)
console.log(`reference messages: ${truthByFlat.size}`)
console.log(`fields checked:     ${checked}`)
console.log(`mismatches:         ${mismatches}`)
if (problems.length) {
    console.log('\nProblems:')
    for (const p of problems.slice(0, 60)) console.log('  -', p)
    if (problems.length > 60) console.log(`  ... and ${problems.length - 60} more`)
}
process.exit(mismatches === 0 ? 0 : 1)
