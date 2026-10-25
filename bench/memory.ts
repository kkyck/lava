/**
 * Memory benchmark.
 *
 * Reports the resident set size of the library at three points:
 *
 * 1. the baseline — Node.js plus the loaded library,
 * 2. after one Signal session has been established,
 * 3. after a full pre-key pool has been generated.
 *
 * Run it with `npm run bench`.
 */

import { SignalKeyStore, generatePreKeyId, generatePreKeyPair, generateRegistrationInfo, generateSignedPreKey } from '../src/signal/keys.js'
import { SignalSessionManager } from '../src/signal/manager.js'
import { SenderKeyManager } from '../src/signal/group.js'
import { SIGNAL_UPLOAD_PREKEYS_COUNT } from '../src/signal/api.js'
import { schemaStats } from '../src/proto/codec.js'

/** The number of pre-keys a full pool holds. */
const FULL_POOL = 812

/** Formats a byte count as a human-readable string. */
function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

/** Forces the garbage collector to run, when the runtime exposes one. */
function collectGarbage(): void {
    const gc = (globalThis as { gc?: () => void }).gc
    if (typeof gc === 'function') gc()
}

/** Returns the current resident set size in bytes. */
function rss(): number {
    return process.memoryUsage().rss
}

/** Returns the current heap usage in bytes. */
function heapUsed(): number {
    return process.memoryUsage().heapUsed
}

const baselineRss = rss()
const baselineHeap = heapUsed()

// ── One Signal session ────────────────────────────────────────────────────────

const keyStore = new SignalKeyStore()
const registration = generateRegistrationInfo()
keyStore.setRegistrationInfo(registration)
keyStore.setSignedPreKey(generateSignedPreKey(generatePreKeyId(), registration.identityKeyPair.privKey))
keyStore.addPreKey(generatePreKeyPair(generatePreKeyId()))

const manager = new SignalSessionManager({
    keyStore,
    senderKeyManager: new SenderKeyManager({ localAddress: '1:0@s.whatsapp.net' }),
})

const peer = generateRegistrationInfo()
const peerPreKey = generatePreKeyPair(generatePreKeyId())
const peerSigned = generateSignedPreKey(generatePreKeyId(), peer.identityKeyPair.privKey)

manager.ensureSession('2:0@s.whatsapp.net', {
    regId: peer.registrationId,
    identity: peer.identityKeyPair.pubKey,
    signedKey: { id: peerSigned.keyId, publicKey: peerSigned.keyPair.pubKey },
    oneTimeKey: { id: peerPreKey.keyId, publicKey: peerPreKey.keyPair.pubKey },
})

const encrypted = manager.encryptForDevice('2:0@s.whatsapp.net', new TextEncoder().encode('hello'))

collectGarbage()
const afterSessionRss = rss()
const afterSessionHeap = heapUsed()

// ── A full pre-key pool ───────────────────────────────────────────────────────

for (let i = 0; i < FULL_POOL - 1; i += 1) {
    keyStore.addPreKey(generatePreKeyPair(generatePreKeyId()))
}

collectGarbage()
const afterPoolRss = rss()
const afterPoolHeap = heapUsed()

const stats = schemaStats()

const rows: [string, number][] = [
    ['baseline (Node + library)', baselineRss],
    ['+ 1 Signal session', afterSessionRss],
    [`+ full pre-key pool (${FULL_POOL})`, afterPoolRss],
]

const width = Math.max(...rows.map(([label]) => label.length))
process.stdout.write('\nLava memory benchmark\n')
process.stdout.write(`${'='.repeat(width + 26)}\n`)
for (const [label, value] of rows) {
    process.stdout.write(`${label.padEnd(width)}  ${formatBytes(value).padStart(10)} RSS\n`)
}
process.stdout.write(`${'='.repeat(width + 26)}\n`)
process.stdout.write(
    `session cost      ${formatBytes(afterSessionRss - baselineRss)}\n` +
        `pre-key pool cost ${formatBytes(afterPoolRss - afterSessionRss)} ` +
        `(${FULL_POOL} pre-keys, ${formatBytes((afterPoolRss - afterSessionRss) / FULL_POOL)} each)\n` +
        `heap growth       ${formatBytes(afterPoolHeap - baselineHeap)}\n` +
        `upload batch      ${SIGNAL_UPLOAD_PREKEYS_COUNT} pre-keys per upload\n` +
        `ciphertext        ${encrypted.ciphertext.length} bytes\n` +
        `schema            ${stats.messages} messages / ${stats.fields} fields\n`,
)
process.stdout.write('\n')
