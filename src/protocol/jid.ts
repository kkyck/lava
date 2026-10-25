/**
 * WhatsApp JID (address) utilities.
 *
 * A JID looks like `user@server` with an optional `:device` suffix on the
 * user part, e.g. `1234567890:12@s.whatsapp.net`.
 *
 * The servers WhatsApp uses:
 *
 * | Server         | Meaning                                   |
 * | -------------- | ----------------------------------------- |
 * | `s.whatsapp.net` | Phone-number (PN) user                  |
 * | `lid`          | Linked identity (the privacy-preserving id) |
 * | `g.us`         | Group                                     |
 * | `broadcast`    | Status / broadcast list                   |
 * | `newsletter`   | Channel                                   |
 * | `hosted`       | Hosted account (WhatsApp Business cloud)   |
 * | `hosted.lid`   | Hosted account, LID addressing            |
 * | `bot`          | Official business bot                     |
 * | `msgr`         | Messenger interop                         |
 * | `interop`      | Cross-platform interop                    |
 */

/** Phone-number user server. */
export const HOST_DOMAIN = 's.whatsapp.net'
/** Group server. */
export const GROUP_SERVER = 'g.us'
/** Broadcast / status server. */
export const BROADCAST_SERVER = 'broadcast'
/** Linked identity server. */
export const LID_SERVER = 'lid'
/** Hosted account server (phone addressing). */
export const HOSTED_SERVER = 'hosted'
/** Hosted account server (LID addressing). */
export const HOSTED_LID_SERVER = 'hosted.lid'
/** Messenger interop server. */
export const MSGR_SERVER = 'msgr'
/** Cross-platform interop server. */
export const INTEROP_SERVER = 'interop'
/** Newsletter / channel server. */
export const NEWSLETTER_SERVER = 'newsletter'
/** Bot server. */
export const BOT_SERVER = 'bot'
/** Special JID used to post a status update. */
export const STATUS_BROADCAST_JID = 'status@broadcast'
/** Device id used for hosted (cloud) devices. */
export const HOSTED_DEVICE_ID = 99

/**
 * Known servers, ordered by how frequently they appear in real traffic.
 *
 * {@link internServerAt} scans this list linearly and returns the first
 * match, so the cost of a lookup is the *position* of the hit. A `Map` would
 * have to hash the whole server string before probing, which is slower for
 * the short, highly-repeated server names used here. Scanning also keeps
 * hostile input such as `"toString"` from resolving through a prototype
 * chain.
 */
const KNOWN_SERVERS: readonly string[] = Object.freeze([
    LID_SERVER,
    HOST_DOMAIN,
    GROUP_SERVER,
    BROADCAST_SERVER,
    NEWSLETTER_SERVER,
    HOSTED_SERVER,
    HOSTED_LID_SERVER,
    BOT_SERVER,
    MSGR_SERVER,
    INTEROP_SERVER,
])

/**
 * Returns the canonical reference for the server segment of `jid` starting
 * at `from`.
 *
 * A known server allocates nothing; only an unknown one pays for the
 * `slice()`.
 *
 * @param jid The full JID.
 * @param from Index of the first character of the server segment.
 */
function internServerAt(jid: string, from: number): string {
    const length = jid.length - from
    for (let index = 0; index < KNOWN_SERVERS.length; index += 1) {
        const server = KNOWN_SERVERS[index]!
        if (server.length === length && jid.startsWith(server, from)) return server
    }
    return jid.slice(from)
}

/** Extracts the ASCII digits from `input`. */
function extractDigits(input: string): string {
    let digits = ''
    for (let index = 0; index < input.length; index += 1) {
        const code = input.charCodeAt(index)
        if (code >= 48 && code <= 57) digits += input[index]!
    }
    return digits
}

/** Locates the `@` separator of a JID. */
function findAtIndex(jid: string): number {
    const atIndex = jid.indexOf('@')
    if (atIndex < 1 || atIndex >= jid.length - 1) {
        throw new Error(`invalid jid: ${jid}`)
    }
    return atIndex
}

/** A JID split into its parts. */
export interface JidParts {
    /** The user part (without the `:device` suffix). */
    user: string
    /** The server part. */
    server: string
    /** The device id; `0` when the JID carries no device segment. */
    device: number
}

/**
 * Splits a JID into `user` and `server`.
 *
 * @param jid The JID to split.
 */
export function splitJid(jid: string): { user: string; server: string } {
    const atIndex = findAtIndex(jid)
    return { user: jid.slice(0, atIndex), server: internServerAt(jid, atIndex + 1) }
}

/**
 * Parses a JID into a Signal-style address.
 *
 * @param jid The JID to parse.
 */
export function parseSignalAddressFromJid(jid: string): JidParts {
    const atIndex = findAtIndex(jid)
    const colonIndex = jid.indexOf(':', 0)
    const server = internServerAt(jid, atIndex + 1)
    if (colonIndex === -1 || colonIndex > atIndex) {
        return { user: jid.slice(0, atIndex), server, device: 0 }
    }
    if (colonIndex >= atIndex - 1) {
        throw new Error(`invalid jid device: ${jid}`)
    }
    let device = 0
    for (let i = colonIndex + 1; i < atIndex; i += 1) {
        const digit = jid.charCodeAt(i) - 48
        if (digit < 0 || digit > 9) throw new Error(`invalid jid device: ${jid}`)
        device = device * 10 + digit
        if (device > Number.MAX_SAFE_INTEGER) throw new Error(`invalid jid device: ${jid}`)
    }
    return { user: jid.slice(0, colonIndex), server, device }
}

/**
 * Parses a JID and returns the address plus the device-less and fully
 * normalized device forms in a single pass.
 *
 * @param jid The JID to parse.
 */
export function parseJidFull(jid: string): {
    address: JidParts
    userJid: string
    normalizedJid: string
} {
    const address = parseSignalAddressFromJid(jid)
    const userJid = `${address.user}@${address.server}`
    const normalizedJid =
        address.device === 0 ? userJid : `${address.user}:${address.device}@${address.server}`
    return { address, userJid, normalizedJid }
}

/**
 * Normalizes a user-supplied recipient into a canonical JID.
 *
 * - A value that already contains `@` is returned unchanged.
 * - A value containing `-` is treated as a group id (`…@g.us`).
 * - Anything else is treated as a phone number (`…@s.whatsapp.net`).
 *
 * @param to The raw recipient.
 */
export function normalizeRecipientJid(to: string): string {
    const input = to.trim()
    if (input.length === 0) throw new Error('recipient cannot be empty')
    let hasDash = false
    for (let index = 0; index < input.length; index += 1) {
        const code = input.charCodeAt(index)
        if (code === 64) return input
        if (code === 45) hasDash = true
    }
    const digits = extractDigits(input)
    if (hasDash) return `${input}@${GROUP_SERVER}`
    if (digits.length === 0) throw new Error(`invalid recipient: ${to}`)
    return `${digits}@${HOST_DOMAIN}`
}

/**
 * Returns `true` when the JID ends with the given server and has exactly one
 * `@`.
 *
 * @param jid The JID to test.
 * @param type The server name.
 */
function isJidType(jid: string, type: string): boolean {
    const atIndex = jid.length - type.length - 1
    if (atIndex < 1 || jid.charCodeAt(atIndex) !== 64 || !jid.endsWith(type)) return false
    for (let i = 0; i < atIndex; i += 1) {
        if (jid.charCodeAt(i) === 64) return false
    }
    return true
}

/** Returns `true` for `@lid` JIDs. */
export function isLidJid(jid: string): boolean {
    return isJidType(jid, LID_SERVER)
}

/** Returns `true` for `@s.whatsapp.net` JIDs. */
export function isUserJid(jid: string): boolean {
    return isJidType(jid, HOST_DOMAIN)
}

/** Returns `true` for `@bot` JIDs. */
export function isBotJid(jid: string): boolean {
    return isJidType(jid, BOT_SERVER)
}

/** Returns `true` for `@g.us` JIDs. */
export function isGroupJid(jid: string): boolean {
    return isJidType(jid, GROUP_SERVER)
}

/** Returns `true` for `@broadcast` JIDs. */
export function isBroadcastJid(jid: string): boolean {
    return isJidType(jid, BROADCAST_SERVER)
}

/** Returns `true` for the special `status@broadcast` JID. */
export function isStatusBroadcastJid(jid: string): boolean {
    return jid === STATUS_BROADCAST_JID
}

/** Returns `true` for `@newsletter` JIDs. */
export function isNewsletterJid(jid: string): boolean {
    return isJidType(jid, NEWSLETTER_SERVER)
}

/** Returns `true` for group or broadcast JIDs. */
export function isGroupOrBroadcastJid(jid: string): boolean {
    return isGroupJid(jid) || isBroadcastJid(jid)
}

/**
 * Maps hosted-account server variants back to their canonical Signal server.
 *
 * @param server The server segment.
 * @param hostDomain The canonical phone-number server.
 */
export function canonicalizeSignalServer(
    server: string,
    hostDomain: string = HOST_DOMAIN,
): string {
    if (server === HOSTED_SERVER) return hostDomain
    if (server === HOSTED_LID_SERVER) return LID_SERVER
    return server
}

/**
 * Returns the JID with its server canonicalized.
 *
 * @param jid The JID to canonicalize.
 * @param hostDomain The canonical phone-number server.
 */
export function canonicalizeSignalJid(jid: string, hostDomain: string = HOST_DOMAIN): string {
    const address = parseSignalAddressFromJid(jid)
    const server = canonicalizeSignalServer(address.server, hostDomain)
    if (address.device === 0) return `${address.user}@${server}`
    return `${address.user}:${address.device}@${server}`
}

/** Options for {@link toUserJid}. */
export interface ToUserJidOptions {
    /** Rewrite hosted servers to their canonical form. */
    canonicalizeSignalServer?: boolean
    /** The canonical phone-number server. */
    hostDomain?: string
}

/** Returns `true` when the server segment is one of the hosted variants. */
function isHostedServerAt(jid: string, from: number): boolean {
    const length = jid.length - from
    if (length === HOSTED_SERVER.length && jid.startsWith(HOSTED_SERVER, from)) return true
    if (length === HOSTED_LID_SERVER.length && jid.startsWith(HOSTED_LID_SERVER, from)) return true
    return false
}

/**
 * Strips the `:device` segment from a JID.
 *
 * @param jid The JID to strip.
 * @param options Canonicalization options.
 */
export function toUserJid(jid: string, options: ToUserJidOptions = {}): string {
    const canonicalize = options.canonicalizeSignalServer === true
    const atIndex = jid.indexOf('@')
    if (atIndex >= 1 && atIndex < jid.length - 1) {
        const colonIndex = jid.indexOf(':', 0)
        if (
            (colonIndex === -1 || colonIndex > atIndex) &&
            (!canonicalize || !isHostedServerAt(jid, atIndex + 1))
        ) {
            return jid
        }
    }
    const address = parseSignalAddressFromJid(jid)
    const baseServer = address.server
    const server = canonicalize
        ? canonicalizeSignalServer(baseServer, options.hostDomain ?? HOST_DOMAIN)
        : baseServer
    if (server === baseServer && jid.length === address.user.length + 1 + server.length) {
        return jid
    }
    return `${address.user}@${server}`
}

const CANONICAL_USER_JID_OPTIONS: ToUserJidOptions = Object.freeze({
    canonicalizeSignalServer: true,
})

/**
 * Returns `true` when the JID refers to the account's own user.
 *
 * Both the phone-number identity (`meJid`) and the LID identity (`meLid`) are
 * accepted, so self traffic is recognised regardless of which addressing
 * mode the account is currently using.
 *
 * @param jid The JID to test.
 * @param meJid The account's phone-number identity.
 * @param meLid The account's LID identity.
 */
export function isOwnAccountJid(
    jid: string,
    meJid?: string | null,
    meLid?: string | null,
): boolean {
    const candidate = toUserJid(jid, CANONICAL_USER_JID_OPTIONS)
    return (
        (!!meJid && toUserJid(meJid, CANONICAL_USER_JID_OPTIONS) === candidate) ||
        (!!meLid && toUserJid(meLid, CANONICAL_USER_JID_OPTIONS) === candidate)
    )
}

/**
 * Rewrites the account's own phone-number JID to its LID equivalent, so self
 * traffic keys a single LID session instead of forking into two ratchets.
 *
 * @param jid The JID to rewrite.
 * @param meJid The account's phone-number identity.
 * @param meLid The account's LID identity.
 */
export function canonicalizeOwnAccountJid(
    jid: string,
    meJid?: string | null,
    meLid?: string | null,
): string {
    if (!meJid || !meLid) return jid
    let address: JidParts
    try {
        address = parseSignalAddressFromJid(jid)
    } catch {
        return jid
    }
    if (address.server !== HOST_DOMAIN) return jid
    let mePnUser: string
    let meLidUser: string
    try {
        mePnUser = parseSignalAddressFromJid(meJid).user
        meLidUser = parseSignalAddressFromJid(meLid).user
    } catch {
        return jid
    }
    if (address.user !== mePnUser) return jid
    return address.device === 0
        ? `${meLidUser}@${LID_SERVER}`
        : `${meLidUser}:${address.device}@${LID_SERVER}`
}

/**
 * Returns the JID in its full device form.
 *
 * @param jid The JID to normalize.
 */
export function normalizeDeviceJid(jid: string): string {
    const address = parseSignalAddressFromJid(jid)
    if (address.device === 0) return `${address.user}@${address.server}`
    return `${address.user}:${address.device}@${address.server}`
}

/**
 * Appends `:device` to a bare user JID.
 *
 * @param userJid The user JID.
 * @param device The device id; `0` leaves the JID unchanged.
 */
export function applyDeviceToJid(userJid: string, device: number): string {
    if (!device) return userJid
    const address = parseSignalAddressFromJid(userJid)
    return buildDeviceJid(address.user, address.server, device)
}

/** Returns `true` when the device id is the hosted-device id. */
export function isHostedDeviceId(deviceId: number): boolean {
    return deviceId === HOSTED_DEVICE_ID
}

/** Returns `true` for the hosted server variants. */
export function isHostedServer(server: string): boolean {
    return server === HOSTED_SERVER || server === HOSTED_LID_SERVER
}

/** Returns `true` when the JID refers to a hosted device. */
export function isHostedDeviceJid(jid: string): boolean {
    const atIndex = jid.indexOf('@')
    if (atIndex < 1 || atIndex >= jid.length - 1) return false
    if (isHostedServerAt(jid, atIndex + 1)) return true
    const colonIndex = jid.indexOf(':')
    if (colonIndex < 0 || colonIndex >= atIndex - 1) return false
    let deviceId = 0
    for (let i = colonIndex + 1; i < atIndex; i += 1) {
        const digit = jid.charCodeAt(i) - 48
        if (digit < 0 || digit > 9) return false
        deviceId = deviceId * 10 + digit
        if (deviceId > Number.MAX_SAFE_INTEGER) return false
    }
    return isHostedDeviceId(deviceId)
}

/** Options for {@link buildDeviceJid}. */
export interface BuildDeviceJidOptions {
    /** Use the hosted-server variant. */
    isHosted?: boolean
    /** The raw (un-normalized) server. */
    rawServer?: string
}

/**
 * Builds a device JID from its parts.
 *
 * @param user The user part.
 * @param normalizedServer The server part.
 * @param deviceId The device id.
 * @param options Hosted-device options.
 */
export function buildDeviceJid(
    user: string,
    normalizedServer: string,
    deviceId: number,
    options: BuildDeviceJidOptions = {},
): string {
    if (options.isHosted === true) {
        if (!isHostedDeviceId(deviceId)) return `${user}:${deviceId}@${normalizedServer}`
        const hostedServer =
            options.rawServer === HOSTED_LID_SERVER || normalizedServer === LID_SERVER
                ? HOSTED_LID_SERVER
                : HOSTED_SERVER
        return `${user}:${HOSTED_DEVICE_ID}@${hostedServer}`
    }
    if (deviceId === 0) return `${user}@${normalizedServer}`
    return `${user}:${deviceId}@${normalizedServer}`
}

/**
 * Extracts the numeric username and device id from the authenticated user's
 * own JID.
 *
 * @param meJid The account's own JID.
 */
export function getLoginIdentity(meJid: string): { username: number; device: number } {
    const atIndex = findAtIndex(meJid)
    const colonIndex = meJid.indexOf(':', 0)
    const dotIndex = meJid.indexOf('.', 0)
    const hasColon = colonIndex !== -1 && colonIndex < atIndex
    const hasDot =
        dotIndex !== -1 && dotIndex < atIndex && (colonIndex === -1 || dotIndex < colonIndex)
    const userEndIndex = hasDot ? dotIndex : hasColon ? colonIndex : atIndex
    const username = Number.parseInt(meJid.slice(0, userEndIndex), 10)
    const device = hasColon ? Number.parseInt(meJid.slice(colonIndex + 1, atIndex), 10) : 0
    if (!Number.isSafeInteger(username) || username <= 0) {
        throw new Error(`invalid numeric username from ${meJid}`)
    }
    if (!Number.isSafeInteger(device) || device < 0) {
        throw new Error(`invalid device from ${meJid}`)
    }
    return { username, device }
}

/**
 * Builds a `<digits>@s.whatsapp.net` JID from a free-form phone number.
 *
 * @param input The phone number.
 */
export function parsePhoneJid(input: string): string {
    const digits = extractDigits(input)
    if (!digits) throw new Error('phone number is empty after normalization')
    return `${digits}@${HOST_DOMAIN}`
}

/**
 * Returns a stable `user|server|device` key for a Signal address.
 *
 * @param address The address to key.
 */
export function signalAddressKey(address: JidParts): string {
    return `${address.user}|${address.server ?? HOST_DOMAIN}|${address.device}`
}
