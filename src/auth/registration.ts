/**
 * Phone-number verification — the *mobile primary* way into an account.
 *
 * Every other WhatsApp library links to an account that already lives on
 * somebody's phone: the library becomes a *companion* device, a guest that
 * borrows the phone's state. This module implements the other half of the
 * protocol: the library claims the phone number itself and becomes the
 * **primary** device, with the account's full state pushed to it over the
 * mobile API.
 *
 * The flow is the one the official apps use:
 *
 * 1. `/exist` — ask the server whether the number is already an account.
 * 2. `/code` — ask for a verification code (SMS or a voice call).
 * 3. `/register` — hand the code back and claim the number.
 *
 * All three requests are encrypted envelopes: the parameters are serialised
 * into a form body, that body is encrypted to the registration server's
 * static key with an ephemeral X25519 key and AES-256-GCM, and the result is
 * posted as a single `ENC=` parameter.
 *
 * Nothing here is copied from another library: the wire format was read off
 * the protocol itself and re-implemented from scratch for Lava.
 */

import { createHash, randomUUID } from 'node:crypto'
import { request as httpsRequest } from 'node:https'

import {
    aesGcmEncrypt,
    concat,
    fromHex,
    generateX25519KeyPair,
    md5,
    randomBytesOf,
    toHex,
    utf8,
    x25519,
} from '../crypto/primitives.js'

/**
 * The registration server's static X25519 public key.
 *
 * Every registration envelope is encrypted to this key, so only the server
 * can read the parameters it carries.
 */
const REGISTRATION_SERVER_KEY = fromHex(
    '8e8c0f74c3ebc5d7a6865c6c3c843856b06121cce8ea774d22fb6f122512302d',
)

/**
 * The static token the iOS build signs its requests with.
 *
 * The token binds a request to the app version it claims to be: the server
 * recomputes it and refuses a request whose token does not match the version
 * in the `User-Agent`. The Android build computes the same thing out of the
 * signed APK, which is why Lava reports itself as iOS unless the caller
 * brings its own token.
 */
const IOS_STATIC_TOKEN = '0a1mLfGUIBVrMKF1RdvLI5lkRBvof6vn0fD2QRSM'

/** The Signal key type the registration announces. */
const SIGNAL_KEY_TYPE = 5

/** The release channel the registration announces. */
const RELEASE_CHANNEL = 0

/** The host that serves the registration endpoints. */
const REGISTRATION_HOST = 'v.whatsapp.net'

/** The port the registration endpoints live on. */
const REGISTRATION_PORT = 443

/** How the code is delivered. */
export type LavaCodeMethod = 'sms' | 'voice' | 'flash' | 'wa_old'

/** The platform the registration speaks for. */
export type LavaRegistrationPlatform = 'ios' | 'android'

/** The device the registration describes. */
export interface LavaRegistrationDevice {
    /** The platform the registration speaks for. */
    os: LavaRegistrationPlatform
    /** The marketing name of the device. */
    model: string
    /** The operating system version. */
    osVersion: string
    /** The build number of the operating system. */
    osBuildNumber?: string
    /** The manufacturer of the device. */
    manufacturer: string
    /** The amount of RAM in gigabytes. */
    ram?: number
    /** The WhatsApp version the registration announces. */
    appVersion: string
}

/** The country metadata a registration request carries. */
export interface LavaCountryMeta {
    /** The mobile country code of the SIM. */
    mcc: string
    /** The mobile network code of the SIM. */
    mnc: string
    /** The language of the device. */
    lg: string
    /** The country of the device. */
    lc: string
}

/** The identity material a registration needs. */
export interface LavaRegistrationIdentity {
    /** The Noise key pair of the device, base64 encoded. */
    noiseKeyPair: { pub: string; priv: string }
    /** The Signal identity key pair of the device, base64 encoded. */
    identityKeyPair: { pub: string; priv: string }
    /** The Signal registration id of the device. */
    registrationId: number
    /** The signed pre-key of the device. */
    signedPreKey: {
        /** The id of the signed pre-key. */
        id: number
        /** The key pair of the signed pre-key, base64 encoded. */
        keyPair: { pub: string; priv: string }
        /** The XEdDSA signature over the signed pre-key, base64 encoded. */
        signature: string
    }
}

/**
 * A registration in progress.
 *
 * The session holds everything the three requests need. It is created before
 * the code is asked for and kept until the number is claimed.
 */
export interface LavaRegistrationSession {
    /** The phone number, in international format. */
    phoneNumber: string
    /** The country calling code of the number. */
    countryCode: string
    /** The national significant number of the number. */
    nationalNumber: string
    /** The identity material of the device. */
    identity: LavaRegistrationIdentity
    /** The random install id of the device. */
    deviceId: Uint8Array
    /** The random identity id of the device. */
    identityId: Uint8Array
    /** The advertising id of the device, hexadecimal. */
    advertisingId: string
    /** The installation folder of the device. */
    installId: string
    /** The session id every request of the flow carries. */
    accessSessionId: string
    /** The country metadata of the device. */
    country: LavaCountryMeta
    /** The device the registration describes. */
    device: LavaRegistrationDevice
    /** The method the code was requested with. */
    codeMethod?: LavaCodeMethod
}

/** The options of a registration. */
export interface LavaRegistrationOptions {
    /** The platform the registration speaks for. */
    os?: LavaRegistrationPlatform
    /** The device the registration describes. */
    device?: Partial<LavaRegistrationDevice>
    /** The WhatsApp version the registration announces. */
    appVersion?: string
    /** The country metadata, when the SIM is known. */
    country?: Partial<LavaCountryMeta>
    /** The token the requests are signed with. */
    token?: string
    /** How the verification code is delivered. */
    method?: LavaCodeMethod
    /** How long a request may take, in milliseconds. */
    timeoutMs?: number
}

/** The answer of the `/exist` endpoint. */
export interface LavaNumberStatus {
    /** Whether the number is already an account. */
    registered: boolean
    /** Whether the server offers a way to register the number. */
    canRegister: boolean
    /** The canonical form of the number, when the server named one. */
    canonicalNumber?: string
    /** The raw answer of the server. */
    raw: Record<string, unknown>
}

/** The answer of the `/code` endpoint. */
export interface LavaCodeRequest {
    /** Whether the server accepted the request. */
    ok: boolean
    /** The method the code is delivered with. */
    method: LavaCodeMethod
    /** The reason the server gave, when it refused. */
    reason?: string
    /** The raw answer of the server. */
    raw: Record<string, unknown>
}

/** The answer of the `/register` endpoint. */
export interface LavaRegistrationResult {
    /** Whether the number was claimed. */
    ok: boolean
    /** The canonical form of the number the server filed the account under. */
    canonicalNumber?: string
    /** The reason the server gave, when it refused. */
    reason?: string
    /** The raw answer of the server. */
    raw: Record<string, unknown>
}

/** The default device the registration describes. */
const DEFAULT_DEVICE: LavaRegistrationDevice = {
    os: 'ios',
    model: 'iPhone',
    osVersion: '18.5',
    osBuildNumber: '22F76',
    manufacturer: 'Apple',
    ram: 8,
    appVersion: '2.26.42.71',
}

/**
 * The country metadata of the countries a registration is likely to come from.
 *
 * The server reads the mobile country code out of the request to decide which
 * operator the number belongs to. A country that is not in the table falls
 * back to the neutral `000`/`000` pair, which the server reads as "no SIM".
 */
const COUNTRY_META: Record<string, LavaCountryMeta> = {
    '1': { mcc: '310', mnc: '004', lg: 'en', lc: 'US' },
    '7': { mcc: '250', mnc: '001', lg: 'ru', lc: 'RU' },
    '20': { mcc: '602', mnc: '001', lg: 'ar', lc: 'EG' },
    '27': { mcc: '655', mnc: '001', lg: 'en', lc: 'ZA' },
    '30': { mcc: '202', mnc: '001', lg: 'el', lc: 'GR' },
    '31': { mcc: '204', mnc: '004', lg: 'nl', lc: 'NL' },
    '32': { mcc: '206', mnc: '001', lg: 'nl', lc: 'BE' },
    '33': { mcc: '208', mnc: '001', lg: 'fr', lc: 'FR' },
    '34': { mcc: '214', mnc: '007', lg: 'es', lc: 'ES' },
    '36': { mcc: '216', mnc: '030', lg: 'hu', lc: 'HU' },
    '39': { mcc: '222', mnc: '001', lg: 'it', lc: 'IT' },
    '40': { mcc: '226', mnc: '001', lg: 'ro', lc: 'RO' },
    '41': { mcc: '228', mnc: '001', lg: 'fr', lc: 'CH' },
    '43': { mcc: '230', mnc: '001', lg: 'de', lc: 'AT' },
    '44': { mcc: '234', mnc: '030', lg: 'en', lc: 'GB' },
    '45': { mcc: '238', mnc: '001', lg: 'da', lc: 'DK' },
    '46': { mcc: '240', mnc: '001', lg: 'sv', lc: 'SE' },
    '47': { mcc: '242', mnc: '001', lg: 'no', lc: 'NO' },
    '48': { mcc: '260', mnc: '001', lg: 'pl', lc: 'PL' },
    '49': { mcc: '262', mnc: '002', lg: 'de', lc: 'DE' },
    '51': { mcc: '710', mnc: '001', lg: 'es', lc: 'PE' },
    '52': { mcc: '334', mnc: '020', lg: 'es', lc: 'MX' },
    '53': { mcc: '368', mnc: '001', lg: 'es', lc: 'CU' },
    '54': { mcc: '722', mnc: '010', lg: 'es', lc: 'AR' },
    '55': { mcc: '724', mnc: '005', lg: 'pt', lc: 'BR' },
    '56': { mcc: '730', mnc: '001', lg: 'es', lc: 'CL' },
    '57': { mcc: '732', mnc: '001', lg: 'es', lc: 'CO' },
    '58': { mcc: '730', mnc: '001', lg: 'es', lc: 'CL' },
    '60': { mcc: '502', mnc: '001', lg: 'ms', lc: 'MY' },
    '61': { mcc: '505', mnc: '001', lg: 'en', lc: 'AU' },
    '62': { mcc: '510', mnc: '001', lg: 'id', lc: 'ID' },
    '63': { mcc: '515', mnc: '001', lg: 'en', lc: 'PH' },
    '64': { mcc: '530', mnc: '001', lg: 'en', lc: 'NZ' },
    '65': { mcc: '525', mnc: '001', lg: 'en', lc: 'SG' },
    '66': { mcc: '520', mnc: '001', lg: 'th', lc: 'TH' },
    '81': { mcc: '440', mnc: '010', lg: 'ja', lc: 'JP' },
    '82': { mcc: '450', mnc: '001', lg: 'ko', lc: 'KR' },
    '84': { mcc: '452', mnc: '001', lg: 'vi', lc: 'VN' },
    '86': { mcc: '460', mnc: '001', lg: 'zh', lc: 'CN' },
    '90': { mcc: '286', mnc: '001', lg: 'tr', lc: 'TR' },
    '91': { mcc: '404', mnc: '001', lg: 'en', lc: 'IN' },
    '92': { mcc: '410', mnc: '001', lg: 'ur', lc: 'PK' },
    '93': { mcc: '413', mnc: '002', lg: 'ur', lc: 'AF' },
    '94': { mcc: '413', mnc: '002', lg: 'si', lc: 'LK' },
    '95': { mcc: '415', mnc: '001', lg: 'ar', lc: 'LB' },
    '98': { mcc: '432', mnc: '001', lg: 'fa', lc: 'IR' },
    '211': { mcc: '659', mnc: '001', lg: 'en', lc: 'SS' },
    '212': { mcc: '602', mnc: '001', lg: 'ar', lc: 'MA' },
    '213': { mcc: '602', mnc: '001', lg: 'ar', lc: 'DZ' },
    '216': { mcc: '605', mnc: '001', lg: 'ar', lc: 'TN' },
    '218': { mcc: '614', mnc: '001', lg: 'en', lc: 'LR' },
    '220': { mcc: '619', mnc: '001', lg: 'en', lc: 'GM' },
    '221': { mcc: '622', mnc: '001', lg: 'fr', lc: 'SN' },
    '233': { mcc: '624', mnc: '001', lg: 'en', lc: 'GH' },
    '234': { mcc: '621', mnc: '001', lg: 'en', lc: 'NG' },
    '235': { mcc: '623', mnc: '001', lg: 'fr', lc: 'CF' },
    '237': { mcc: '624', mnc: '001', lg: 'fr', lc: 'CM' },
    '249': { mcc: '659', mnc: '001', lg: 'ar', lc: 'SD' },
    '254': { mcc: '639', mnc: '001', lg: 'sw', lc: 'KE' },
    '255': { mcc: '640', mnc: '001', lg: 'sw', lc: 'TZ' },
    '256': { mcc: '641', mnc: '001', lg: 'en', lc: 'UG' },
    '260': { mcc: '645', mnc: '001', lg: 'en', lc: 'ZM' },
    '263': { mcc: '645', mnc: '001', lg: 'en', lc: 'ZW' },
    '265': { mcc: '646', mnc: '001', lg: 'en', lc: 'MW' },
    '351': { mcc: '268', mnc: '001', lg: 'pt', lc: 'PT' },
    '352': { mcc: '208', mnc: '001', lg: 'fr', lc: 'LU' },
    '353': { mcc: '234', mnc: '005', lg: 'en', lc: 'IE' },
    '354': { mcc: '238', mnc: '001', lg: 'is', lc: 'IS' },
    '355': { mcc: '276', mnc: '001', lg: 'sq', lc: 'AL' },
    '372': { mcc: '233', mnc: '001', lg: 'et', lc: 'EE' },
    '380': { mcc: '255', mnc: '001', lg: 'uk', lc: 'UA' },
    '385': { mcc: '220', mnc: '001', lg: 'hr', lc: 'HR' },
    '420': { mcc: '420', mnc: '001', lg: 'ar', lc: 'SA' },
    '421': { mcc: '502', mnc: '001', lg: 'ms', lc: 'MY' },
    '852': { mcc: '454', mnc: '001', lg: 'zh', lc: 'HK' },
    '853': { mcc: '455', mnc: '001', lg: 'zh', lc: 'MO' },
    '855': { mcc: '460', mnc: '001', lg: 'km', lc: 'KH' },
    '856': { mcc: '410', mnc: '001', lg: 'lo', lc: 'LA' },
    '880': { mcc: '470', mnc: '002', lg: 'bn', lc: 'BD' },
    '886': { mcc: '466', mnc: '001', lg: 'zh', lc: 'TW' },
    '960': { mcc: '421', mnc: '001', lg: 'ar', lc: 'MV' },
    '961': { mcc: '415', mnc: '001', lg: 'ar', lc: 'LB' },
    '962': { mcc: '419', mnc: '001', lg: 'ar', lc: 'JO' },
    '963': { mcc: '418', mnc: '001', lg: 'ar', lc: 'SY' },
    '964': { mcc: '422', mnc: '001', lg: 'ar', lc: 'IQ' },
    '965': { mcc: '419', mnc: '001', lg: 'ar', lc: 'KW' },
    '966': { mcc: '420', mnc: '001', lg: 'ar', lc: 'SA' },
    '967': { mcc: '421', mnc: '001', lg: 'ar', lc: 'YE' },
    '968': { mcc: '421', mnc: '001', lg: 'ar', lc: 'OM' },
    '970': { mcc: '425', mnc: '001', lg: 'ar', lc: 'PS' },
    '971': { mcc: '424', mnc: '001', lg: 'ar', lc: 'AE' },
    '972': { mcc: '425', mnc: '001', lg: 'he', lc: 'IL' },
    '973': { mcc: '426', mnc: '001', lg: 'ar', lc: 'BH' },
    '974': { mcc: '427', mnc: '001', lg: 'ar', lc: 'QA' },
    '977': { mcc: '404', mnc: '001', lg: 'ne', lc: 'NP' },
    '992': { mcc: '437', mnc: '001', lg: 'tg', lc: 'TJ' },
    '994': { mcc: '400', mnc: '001', lg: 'az', lc: 'AZ' },
    '995': { mcc: '283', mnc: '001', lg: 'hy', lc: 'AM' },
    '996': { mcc: '437', mnc: '001', lg: 'ky', lc: 'KG' },
    '998': { mcc: '433', mnc: '001', lg: 'uz', lc: 'UZ' },
}

/**
 * The country calling codes that are three digits long.
 *
 * The list decides where the country calling code ends and the national
 * number begins, which is the first thing the server checks.
 */
const THREE_DIGIT_COUNTRY_CODES = new Set([
    '211', '212', '213', '216', '218', '220', '221', '222', '223', '224', '225', '226',
    '227', '228', '229', '230', '231', '232', '233', '234', '235', '236', '237', '238',
    '239', '240', '241', '242', '243', '244', '245', '246', '247', '248', '249', '250',
    '251', '252', '253', '254', '255', '256', '257', '258', '260', '261', '262', '263',
    '264', '265', '266', '267', '268', '269', '290', '291', '297', '298', '299', '350',
    '351', '352', '353', '354', '355', '356', '357', '358', '359', '370', '371', '372',
    '373', '374', '375', '376', '377', '378', '380', '381', '382', '383', '385', '386',
    '387', '389', '420', '421', '423', '500', '501', '502', '503', '504', '505', '506',
    '507', '508', '509', '590', '591', '592', '593', '594', '595', '596', '597', '598',
    '599', '670', '672', '673', '674', '675', '676', '677', '678', '679', '680', '681',
    '682', '683', '685', '686', '687', '688', '689', '690', '691', '692', '850', '852',
    '853', '855', '856', '880', '886', '960', '961', '962', '963', '964', '965', '966',
    '967', '968', '970', '971', '972', '973', '974', '975', '976', '977', '992', '993',
    '994', '995', '996', '998',
])

/**
 * The country calling codes that are two digits long.
 */
const TWO_DIGIT_COUNTRY_CODES = new Set([
    '20', '27', '30', '31', '32', '33', '34', '36', '39', '40', '41', '43', '44', '45',
    '46', '47', '48', '49', '51', '52', '53', '54', '55', '56', '57', '58', '60', '61',
    '62', '63', '64', '65', '66', '81', '82', '84', '86', '90', '91', '92', '93', '94',
    '95', '98',
])

/**
 * Splits a phone number into its country calling code and its national number.
 *
 * @param phoneNumber The phone number, in any format.
 */
export function parsePhoneNumber(phoneNumber: string): {
    countryCode: string
    nationalNumber: string
} {
    const digits = String(phoneNumber).replace(/\D/g, '')
    if (digits.length < 4) {
        throw new Error(`lava: "${phoneNumber}" is not a phone number`)
    }
    const three = digits.slice(0, 3)
    if (THREE_DIGIT_COUNTRY_CODES.has(three)) {
        return { countryCode: three, nationalNumber: String(BigInt(digits.slice(3))) }
    }
    const two = digits.slice(0, 2)
    if (TWO_DIGIT_COUNTRY_CODES.has(two)) {
        return { countryCode: two, nationalNumber: String(BigInt(digits.slice(2))) }
    }
    const one = digits.slice(0, 1)
    if (one === '0') {
        // A national number without its country code is ambiguous: the same
        // digits belong to a dozen countries. The server would file the
        // account under the wrong one, so the number is refused instead.
        throw new Error(
            `lava: "${phoneNumber}" has no country code — ` +
                'use the international format, for example +6281234567890',
        )
    }
    return { countryCode: one, nationalNumber: String(BigInt(digits.slice(1))) }
}

/**
 * Computes the token a registration request is signed with.
 *
 * The token binds the request to the app version it announces: the server
 * recomputes it from the `User-Agent` and the national number and refuses a
 * request whose token does not match.
 *
 * @param appVersion The app version the registration announces.
 * @param nationalNumber The national significant number.
 * @param os The platform the registration speaks for.
 * @param token The token the caller brings, when the platform needs one.
 */
export function computeRegistrationToken(
    appVersion: string,
    nationalNumber: string,
    os: LavaRegistrationPlatform,
    token?: string,
): string {
    if (token) return token
    if (os === 'android') {
        throw new Error(
            'lava: an Android registration needs a token of its own — pass it as options.token',
        )
    }
    const versionHash = toHex(md5(utf8(appVersion)))
    return toHex(md5(utf8(`${IOS_STATIC_TOKEN}${versionHash}${nationalNumber}`)))
}

/**
 * Encrypts a registration payload for the registration server.
 *
 * The payload is encrypted to the server's static key with an ephemeral
 * X25519 key pair: the ephemeral public key travels with the ciphertext, so
 * only the server can decrypt it.
 *
 * @param plaintext The serialised form body.
 * @returns The base64url envelope.
 */
export function encryptRegistrationPayload(plaintext: string): string {
    const ephemeral = generateX25519KeyPair()
    const shared = x25519(ephemeral.privateKey, REGISTRATION_SERVER_KEY)
    const iv = new Uint8Array(12)
    const sealed = aesGcmEncrypt(shared, iv, utf8(plaintext))
    return toBase64Url(concat(ephemeral.publicKey, sealed))
}

/**
 * Encodes bytes as base64url without padding.
 *
 * @param value The bytes.
 */
export function toBase64Url(value: Uint8Array): string {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '')
}

/**
 * Encodes bytes the way a Java `toUrlHex` does: one `%XX` group per byte.
 *
 * @param value The bytes.
 */
export function toUrlHex(value: Uint8Array): string {
    let out = ''
    for (const byte of value) out += `%${byte.toString(16).toUpperCase().padStart(2, '0')}`
    return out
}

/**
 * Serialises a list of parameters into a form body.
 *
 * The registration server reads the body as `key=value` pairs joined by an
 * ampersand. The pairs are **not** percent-encoded: the `id` parameter
 * carries percent groups of its own, and encoding them again would change
 * what the server sees.
 *
 * @param pairs The parameters, as a flat list of key and value.
 */
export function buildRegistrationForm(pairs: readonly (string | null)[]): string {
    const parts: string[] = []
    for (let i = 0; i + 1 < pairs.length; i += 2) {
        const value = pairs[i + 1]
        if (value === null || value === undefined) continue
        parts.push(`${pairs[i]}=${value}`)
    }
    return parts.join('&')
}

/**
 * The registration client.
 *
 * The client walks a phone number through the three verification steps and
 * hands back the identity material the account is then used with.
 */
export class LavaRegistration {
    /**
     * Creates a registration session for a phone number.
     *
     * @param phoneNumber The phone number, in international format.
     * @param identity The identity material of the device.
     * @param options The options.
     */
    static createSession(
        phoneNumber: string,
        identity: LavaRegistrationIdentity,
        options: LavaRegistrationOptions = {},
    ): LavaRegistrationSession {
        const { countryCode, nationalNumber } = parsePhoneNumber(phoneNumber)
        const device: LavaRegistrationDevice = {
            ...DEFAULT_DEVICE,
            ...(options.device ?? {}),
            os: options.device?.os ?? options.os ?? DEFAULT_DEVICE.os,
            appVersion:
                options.appVersion ??
                options.device?.appVersion ??
                DEFAULT_DEVICE.appVersion,
        }
        const country: LavaCountryMeta = {
            ...(COUNTRY_META[countryCode] ?? {
                mcc: '000',
                mnc: '000',
                lg: 'en',
                lc: 'US',
            }),
            ...(options.country ?? {}),
        }
        const identityId = randomBytesOf(16)
        return {
            phoneNumber: `+${countryCode}${nationalNumber}`,
            countryCode,
            nationalNumber,
            identity,
            deviceId: randomBytesOf(16),
            identityId,
            advertisingId: toHex(randomBytesOf(16)),
            installId: toHex(randomBytesOf(8)),
            accessSessionId: toBase64Url(randomBytesOf(16)),
            country,
            device,
        }
    }

    /**
     * Asks the server whether a number is already an account.
     *
     * @param session The registration session.
     * @param options The options.
     */
    static async checkNumber(
        session: LavaRegistrationSession,
        options: LavaRegistrationOptions = {},
    ): Promise<LavaNumberStatus> {
        const payload = buildCommonPairs(session, options, false)
        const raw = await postRegistration('/exist', session, payload, options)
        const status = String(raw.status ?? '')
        return {
            registered: status === 'ok' || raw.state === 'existing',
            canRegister:
                status === 'fail' ||
                raw.state === 'missing' ||
                raw.can_register === true ||
                status === '',
            ...(typeof raw.login === 'string' ? { canonicalNumber: raw.login } : {}),
            raw,
        }
    }

    /**
     * Asks the server for a verification code.
     *
     * @param session The registration session.
     * @param method How the code should be delivered.
     * @param options The options.
     */
    static async requestCode(
        session: LavaRegistrationSession,
        method: LavaCodeMethod = 'sms',
        options: LavaRegistrationOptions = {},
    ): Promise<LavaCodeRequest> {
        if (method === 'flash' && session.device.os !== 'android') {
            throw new Error(
                'lava: a flash call is only offered to Android devices — ' +
                    'there is no public way to read the number of an incoming call on iOS',
            )
        }
        const payload = buildCommonPairs(session, options, true)
        payload.push(...buildCodePairs(session, method))
        const raw = await postRegistration('/code', session, payload, options)
        const status = String(raw.status ?? '')
        session.codeMethod = method
        return {
            ok: status === 'ok' || status === 'sent',
            method,
            ...(typeof raw.reason === 'string' ? { reason: raw.reason } : {}),
            raw,
        }
    }

    /**
     * Hands the verification code back and claims the number.
     *
     * @param session The registration session.
     * @param code The code the user received.
     * @param options The options.
     */
    static async submitCode(
        session: LavaRegistrationSession,
        code: string,
        options: LavaRegistrationOptions = {},
    ): Promise<LavaRegistrationResult> {
        const payload = buildCommonPairs(session, options, session.device.os !== 'android')
        payload.push(...buildRegisterPairs(session, code))
        const raw = await postRegistration('/register', session, payload, options)
        const status = String(raw.status ?? '')
        return {
            ok: status === 'ok' || status === 'sent' || status === 'verified',
            ...(typeof raw.login === 'string' ? { canonicalNumber: raw.login } : {}),
            ...(typeof raw.reason === 'string' ? { reason: raw.reason } : {}),
            raw,
        }
    }
}

/**
 * Builds the parameters every registration request carries.
 *
 * @param session The registration session.
 * @param options The options.
 * @param withToken Whether the request carries the version token.
 */
function buildCommonPairs(
    session: LavaRegistrationSession,
    options: LavaRegistrationOptions,
    withToken: boolean,
): (string | null)[] {
    const identity = session.identity
    const noiseKey = fromBase64Bytes(identity.noiseKeyPair.pub)
    const pairs: (string | null)[] = [
        'cc',
        session.countryCode,
        'in',
        session.nationalNumber,
        'rc',
        String(RELEASE_CHANNEL),
        'lg',
        session.country.lg,
        'lc',
        session.country.lc,
        'authkey',
        toBase64Url(stripKeyPrefix(noiseKey)),
        'e_regid',
        toBase64Url(intToBytes(identity.registrationId, 4)),
        'e_keytype',
        toBase64Url(new Uint8Array([SIGNAL_KEY_TYPE])),
        'e_ident',
        toBase64Url(stripKeyPrefix(fromBase64Bytes(identity.identityKeyPair.pub))),
        'e_skey_id',
        toBase64Url(intToBytes(identity.signedPreKey.id, 3)),
        'e_skey_val',
        toBase64Url(stripKeyPrefix(fromBase64Bytes(identity.signedPreKey.keyPair.pub))),
        'e_skey_sig',
        toBase64Url(fromBase64Bytes(identity.signedPreKey.signature)),
        'fdid',
        session.device.os === 'android'
            ? session.advertisingId.toLowerCase()
            : session.advertisingId.toUpperCase(),
        'expid',
        toBase64Url(session.deviceId),
        'id',
        toUrlHex(session.identityId),
        'access_session_id',
        session.accessSessionId,
    ]
    if (withToken) {
        pairs.push(
            'token',
            computeRegistrationToken(
                session.device.appVersion,
                session.nationalNumber,
                session.device.os,
                options.token,
            ),
        )
    }
    return pairs
}

/**
 * Builds the parameters of the `/code` request.
 *
 * @param session The registration session.
 * @param method How the code should be delivered.
 */
function buildCodePairs(
    session: LavaRegistrationSession,
    method: LavaCodeMethod,
): (string | null)[] {
    if (session.device.os === 'android') {
        return [
            'method',
            method,
            'sim_mcc',
            session.country.mcc,
            'sim_mnc',
            session.country.mnc,
            'reason',
            '',
            'mcc',
            session.country.mcc,
            'mnc',
            session.country.mnc,
            'feo2_query_status',
            'success_get_client_capabilities',
            'db',
            '1',
            'sim_type',
            session.country.mcc === '000' ? '0' : '1',
            'recaptcha',
            '%7B%22stage%22%3A%22ABPROP_DISABLED%22%7D',
            'network_radio_type',
            '1',
            'prefer_sms_over_flash',
            method === 'flash' ? 'true' : 'false',
            'simnum',
            session.country.mcc === '000' ? '0' : '1',
            'airplane_mode_type',
            '0',
            'client_metrics',
            buildClientMetrics(1, session),
            'mistyped',
            '7',
            'advertising_id',
            session.advertisingId,
            'hasinrc',
            '1',
            'roaming_type',
            '0',
            'device_ram',
            (session.device.ram ?? 8).toFixed(2),
            'education_screen_displayed',
            'false',
            'pid',
            buildAppPid(session),
            'cellular_strength',
            '5',
            'backup_token',
            '',
            'tos_version',
            '5',
            'call_log_permission',
            method === 'flash' ? 'true' : 'false',
            'manage_call_permission',
            method === 'flash' ? 'true' : 'false',
            'clicked_education_link',
            'false',
            'aid',
            buildDeviceAid(session),
            'hasav',
            '2',
            'entrypoint',
            'suma',
        ]
    }
    return [
        'method',
        method,
        'sim_mcc',
        session.country.mcc,
        'sim_mnc',
        session.country.mnc,
        'jailbroken',
        '0',
        'cellular_strength',
        '1',
    ]
}

/**
 * Builds the parameters of the `/register` request.
 *
 * @param session The registration session.
 * @param code The code the user received.
 */
function buildRegisterPairs(
    session: LavaRegistrationSession,
    code: string,
): (string | null)[] {
    const pairs: (string | null)[] = [
        'code',
        String(code).replace(/\D/g, ''),
        'sim_operator_name',
        '',
        'passkey_login_status',
        'not_attempted',
        'network_operator_name',
        '',
        'entered',
        '1',
        'has_play_store',
        'true',
        'entrypoint',
        'suma',
    ]
    if (session.device.os === 'android') {
        pairs.push(
            'sim_mcc',
            session.country.mcc,
            'sim_mnc',
            session.country.mnc,
            'device_ram',
            (session.device.ram ?? 8).toFixed(2),
            'db',
            '1',
            'network_radio_type',
            '1',
            'pid',
            buildAppPid(session),
            'cellular_strength',
            '5',
            'hasinrc',
            '1',
            'aid',
            buildDeviceAid(session),
            'mcc',
            session.country.mcc,
            'mnc',
            session.country.mnc,
            'roaming_type',
            '0',
            'mistyped',
            '7',
            'airplane_mode_type',
            '0',
            'sim_type',
            session.country.mcc === '000' ? '0' : '1',
            'simnum',
            session.country.mcc === '000' ? '0' : '1',
            'recaptcha',
            '%7B%22stage%22%3A%22ABPROP_DISABLED%22%7D',
            'client_metrics',
            buildClientMetrics(0, session),
        )
    }
    return pairs
}

/**
 * Builds the `client_metrics` parameter.
 *
 * @param attempt The number of the attempt.
 * @param session The registration session.
 */
function buildClientMetrics(attempt: number, session: LavaRegistrationSession): string {
    const simAbsent = !/^\d+$/.test(session.country.mcc) || /^0+$/.test(session.country.mcc)
    const json =
        `{"attempts":${attempt}` +
        ',"app_campaign_download_source":"google-play|unknown"' +
        `,"is_sim_absent":${simAbsent ? 'true' : 'false'}}`
    return encodeURIComponent(json)
}

/**
 * Derives the process id the registration announces.
 *
 * Android hands out process ids from a counter that starts near 300, so a
 * process id of one or two is a tell that no real app sent the request.
 *
 * @param session The registration session.
 */
function buildAppPid(session: LavaRegistrationSession): string {
    const hash = createHash('sha256').update(session.identityId).update('pid').digest()
    return String(1024 + (hash.readUInt32BE(0) % (32768 - 1024)))
}

/**
 * Derives the advertising id the registration announces.
 *
 * @param session The registration session.
 */
function buildDeviceAid(session: LavaRegistrationSession): string {
    return createHash('sha256')
        .update(session.identityId)
        .update('aid')
        .digest('base64')
}

/**
 * Removes the version prefix a serialized key carries.
 *
 * @param value The serialized key.
 */
function stripKeyPrefix(value: Uint8Array): Uint8Array {
    if (value.length === 33 && value[0] === 0x05) return value.subarray(1)
    return value
}

/**
 * Encodes a number as a big-endian byte string.
 *
 * @param value The number.
 * @param length The number of bytes.
 */
function intToBytes(value: number, length: number): Uint8Array {
    const out = new Uint8Array(length)
    let rest = value
    for (let i = length - 1; i >= 0; i--) {
        out[i] = rest & 0xff
        rest = Math.floor(rest / 256)
    }
    return out
}

/**
 * Decodes base64 into bytes.
 *
 * @param value The base64 text.
 */
function fromBase64Bytes(value: string): Uint8Array {
    const buffer = Buffer.from(value, 'base64')
    return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength)
}

/**
 * Posts an encrypted registration request and parses the answer.
 *
 * @param path The endpoint, with its leading slash.
 * @param session The registration session.
 * @param pairs The parameters of the request.
 * @param options The options.
 */
async function postRegistration(
    path: string,
    session: LavaRegistrationSession,
    pairs: readonly (string | null)[],
    options: LavaRegistrationOptions,
): Promise<Record<string, unknown>> {
    const plaintext = buildRegistrationForm(pairs)
    const body = `ENC=${encryptRegistrationPayload(plaintext)}`
    const headers = buildRegistrationHeaders(session.device, options.timeoutMs)
    const response = await httpsPost(
        `/v2${path}`,
        body,
        headers,
        options.timeoutMs ?? 20000,
    )
    try {
        return JSON.parse(response) as Record<string, unknown>
    } catch {
        return { status: 'unknown', raw: response }
    }
}

/**
 * Builds the headers a registration request carries.
 *
 * The server reads the platform out of the `User-Agent`: a request whose
 * agent names no platform it knows is refused on every endpoint.
 *
 * @param device The device the registration describes.
 * @param timeoutMs How long the request may take.
 */
function buildRegistrationHeaders(
    device: LavaRegistrationDevice,
    timeoutMs?: number,
): Record<string, string> {
    void timeoutMs
    const platform = device.os === 'android' ? 'Android' : 'iOS'
    return {
        'User-Agent':
            `WhatsApp/${device.appVersion} ${platform}/${device.osVersion} ` +
            `Device/${device.manufacturer}-${device.model}`,
        'Content-Type': 'application/x-www-form-urlencoded',
    }
}

/**
 * Posts a body over HTTPS and returns the answer.
 *
 * @param path The path of the request.
 * @param body The body of the request.
 * @param headers The headers of the request.
 * @param timeoutMs How long the request may take.
 */
function httpsPost(
    path: string,
    body: string,
    headers: Record<string, string>,
    timeoutMs: number,
): Promise<string> {
    return new Promise((resolve, reject) => {
        const bodyBuffer = Buffer.from(body, 'utf8')
        const request = httpsRequest(
            {
                hostname: REGISTRATION_HOST,
                port: REGISTRATION_PORT,
                path,
                method: 'POST',
                timeout: timeoutMs,
                headers: {
                    ...headers,
                    'Content-Length': bodyBuffer.length,
                },
            },
            (response) => {
                const chunks: Buffer[] = []
                response.on('data', (chunk: Buffer) => chunks.push(chunk))
                response.on('end', () => {
                    const text = Buffer.concat(chunks).toString('utf8')
                    const status = response.statusCode ?? 0
                    if (status !== 200) {
                        reject(new Error(`lava: the registration server answered ${status}: ${text}`))
                        return
                    }
                    resolve(text)
                })
            },
        )
        request.on('error', reject)
        request.on('timeout', () => {
            request.destroy(new Error('lava: the registration request timed out'))
        })
        request.write(bodyBuffer)
        request.end()
    })
}

/**
 * Generates the random request id the registration headers carry.
 *
 * The official client mints a fresh uppercase UUID for every request.
 */
export function newRegistrationRequestId(): string {
    return randomUUID().toUpperCase()
}
