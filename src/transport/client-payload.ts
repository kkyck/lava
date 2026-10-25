/**
 * Client payload construction.
 *
 * The `ClientPayload` protobuf is the very first thing an official client
 * sends after the Noise handshake. It describes who the device is: its
 * platform, app version, locale, hardware and Signal identity.
 *
 * WhatsApp's servers fingerprint this payload: a client that reports an
 * impossible combination (say, a `WEB` platform with an Android build
 * number) or an app version that does not exist is flagged. The builders
 * below therefore default to *exactly* the values the official clients
 * report, and any deviation has to be requested explicitly.
 */

import { md5, utf8 } from '../crypto/primitives.js'
import { encode } from '../proto/codec.js'
import {
    ClientPayload_ConnectReason,
    ClientPayload_ConnectType,
    ClientPayload_UserAgent_Platform,
    ClientPayload_UserAgent_ReleaseChannel,
    DeviceProps_PlatformType,
} from '../proto/enums.js'

/** The WhatsApp Web version this library reports by default. */
export const DEFAULT_WEB_VERSION = '2.3000.1043028647'

/** The WhatsApp for Android version this library reports by default. */
export const DEFAULT_ANDROID_VERSION = '2.25.28.82'

/** A parsed application version. */
export interface AppVersion {
    /** Major version. */
    primary: number
    /** Minor version. */
    secondary: number
    /** Patch version. */
    tertiary: number
    /** Build number, when present. */
    quaternary?: number
    /** Extra build component, when present. */
    quinary?: number
}

/**
 * Parses a dotted version string into its components.
 *
 * @param version The version string, e.g. `2.3000.1043028647`.
 */
export function parseAppVersion(version: string): AppVersion {
    const parts = version.split('.')
    const at = (index: number): number | undefined => {
        const raw = parts[index]
        if (raw === undefined) return undefined
        const value = Number(raw)
        return Number.isFinite(value) ? value : undefined
    }
    const quaternary = at(3)
    const quinary = at(4)
    const parsed: AppVersion = {
        primary: at(0) ?? 2,
        secondary: at(1) ?? 0,
        tertiary: at(2) ?? 0,
    }
    if (quaternary !== undefined) parsed.quaternary = quaternary
    if (quinary !== undefined) parsed.quinary = quinary
    return parsed
}

/**
 * Builds a big-endian integer of `byteLength` bytes.
 *
 * WhatsApp encodes several integers (registration id, key ids) as fixed-width
 * big-endian byte strings, and the width is part of the wire format.
 *
 * @param byteLength Width of the encoded integer.
 * @param value The value to encode.
 */
export function intToBytes(byteLength: number, value: number): Uint8Array {
    const out = new Uint8Array(byteLength)
    let remaining = value
    for (let i = byteLength - 1; i >= 0; i -= 1) {
        out[i] = remaining & 0xff
        remaining = Math.floor(remaining / 256)
    }
    return out
}

/**
 * The hardware and locale description of a device.
 *
 * Every field maps onto a `ClientPayload.UserAgent` entry, so a profile is
 * the single source of truth for how the device presents itself.
 */
export interface DeviceProfile {
    /** `android` or `ios`. */
    os: 'android' | 'ios'
    /** Marketing name of the device, e.g. `Pixel 8 Pro`. */
    device: string
    /** OS version string, e.g. `14`. */
    osVersion: string
    /** OS build number, e.g. `UQ1A.240105.004`. */
    osBuildNumber: string
    /** Manufacturer, e.g. `Google`. */
    manufacturer: string
    /** Hardware board identifier (Android only). */
    deviceBoard?: string
    /** Mobile country code. */
    mcc?: string
    /** Mobile network code. */
    mnc?: string
    /** Two-letter language code. */
    localeLanguageIso6391?: string
    /** Two-letter country code. */
    localeCountryIso31661Alpha2?: string
    /** Stable per-install device id (UUID). */
    phoneId?: string
    /** Device model type hint. */
    deviceModelType?: string
    /** App version string. */
    appVersion?: string
    /** Whether this is a WhatsApp Business account. */
    business?: boolean
    /** App distribution channel (iOS only). */
    distributionChannel?: 'appstore' | 'testflight' | 'internal' | 'website'
}

/** The Android profile used by default. */
export const DEFAULT_ANDROID_PROFILE: DeviceProfile = Object.freeze({
    os: 'android',
    device: 'Pixel 8 Pro',
    osVersion: '14',
    osBuildNumber: 'UQ1A.240105.004',
    manufacturer: 'Google',
    deviceBoard: 'husky',
    mcc: '000',
    mnc: '000',
    localeLanguageIso6391: 'en',
    localeCountryIso31661Alpha2: 'US',
    appVersion: DEFAULT_ANDROID_VERSION,
    distributionChannel: 'appstore',
})

/** The iOS profile used by default. */
export const DEFAULT_IOS_PROFILE: DeviceProfile = Object.freeze({
    os: 'ios',
    device: 'iPhone15,3',
    osVersion: '17.4.1',
    osBuildNumber: '21E236',
    manufacturer: 'Apple Inc.',
    mcc: '000',
    mnc: '000',
    localeLanguageIso6391: 'en',
    localeCountryIso31661Alpha2: 'US',
    appVersion: DEFAULT_ANDROID_VERSION,
    distributionChannel: 'appstore',
})

/** Configuration shared by every payload builder. */
export interface CommonPayloadConfig {
    /** The device profile to report. */
    deviceProfile: DeviceProfile
    /** Passive mode: do not push notifications to the account's other devices. */
    passive?: boolean
    /** Request a full history sync on connect. */
    pull?: boolean
    /** Connect type (network class). */
    connectType?: number
    /** Reason for the connection. */
    connectReason?: number
    /** Push name shown to other users. */
    pushName?: string
}

/**
 * Builds the `UserAgent` sub-message for a mobile device.
 *
 * @param profile The device profile.
 */
function buildMobileUserAgent(profile: DeviceProfile): Record<string, unknown> {
    const isIos = profile.os === 'ios'
    const platform = isIos
        ? profile.business
            ? ClientPayload_UserAgent_Platform.SMB_IOS
            : ClientPayload_UserAgent_Platform.IOS
        : profile.business
          ? ClientPayload_UserAgent_Platform.SMB_ANDROID
          : ClientPayload_UserAgent_Platform.ANDROID
    const version = parseAppVersion(profile.appVersion ?? DEFAULT_ANDROID_VERSION)
    const agent: Record<string, unknown> = {
        platform,
        releaseChannel: ClientPayload_UserAgent_ReleaseChannel.RELEASE,
        appVersion: version,
        osVersion: profile.osVersion,
        manufacturer: profile.manufacturer,
        device: profile.device,
        osBuildNumber: profile.osBuildNumber,
        phoneId: profile.phoneId ?? crypto.randomUUID(),
        localeLanguageIso6391: profile.localeLanguageIso6391 ?? 'en',
        localeCountryIso31661Alpha2: profile.localeCountryIso31661Alpha2 ?? 'US',
        deviceType: 0,
    }
    if (profile.deviceModelType !== undefined) agent.deviceModelType = profile.deviceModelType
    if (isIos) {
        agent.distributionChannel = distributionChannelId(profile.distributionChannel)
    } else {
        agent.mcc = profile.mcc ?? '000'
        agent.mnc = profile.mnc ?? '000'
        agent.deviceBoard = profile.deviceBoard ?? 'husky'
    }
    return agent
}

/**
 * Maps a distribution channel name to its protocol value.
 *
 * @param channel The channel name.
 */
function distributionChannelId(channel: DeviceProfile['distributionChannel']): number {
    switch (channel) {
        case 'website':
            return 1
        case 'testflight':
            return 2
        case 'internal':
            return 3
        default:
            return 0
    }
}

/**
 * Builds the `UserAgent` sub-message for WhatsApp Web.
 *
 * @param versionBase The WhatsApp Web version string.
 */
function buildWebUserAgent(versionBase: string): Record<string, unknown> {
    const version = parseAppVersion(versionBase)
    const locale = resolveLocale()
    return {
        platform: ClientPayload_UserAgent_Platform.WEB,
        releaseChannel: ClientPayload_UserAgent_ReleaseChannel.RELEASE,
        appVersion: version,
        mcc: '000',
        mnc: '000',
        osVersion: '0.1',
        manufacturer: '',
        device: 'Desktop',
        osBuildNumber: '0.1',
        localeLanguageIso6391: locale.lg,
        localeCountryIso31661Alpha2: locale.lc,
    }
}

/** Cached process locale; `Intl` initialisation is expensive. */
let cachedLocale: { lg: string; lc: string } | null = null

/** Resolves (and memoises) the process locale. */
function resolveLocale(): { lg: string; lc: string } {
    if (cachedLocale !== null) return cachedLocale
    const locale = Intl.DateTimeFormat().resolvedOptions().locale || 'en-US'
    const [language = 'en', country = 'US'] = locale.split('-')
    cachedLocale = Object.freeze({
        lg: language.toLowerCase(),
        lc: country.toUpperCase(),
    })
    return cachedLocale
}

/** Configuration for the mobile login payload. */
export interface MobileLoginPayloadConfig extends CommonPayloadConfig {
    /** The numeric WhatsApp user id of the account. */
    username: number
    /** The device id of this device. */
    device?: number
    /** Whether the account has completed the LID database migration. */
    lidDbMigrated?: boolean
    /** Device memory class (Android). */
    memClass?: number
    /** Device year class (Android). */
    yearClass?: number
}

/**
 * Builds the payload for an existing account on the **mobile** transport.
 *
 * @param config The payload configuration.
 */
export function buildMobileLoginPayload(config: MobileLoginPayloadConfig): Uint8Array {
    if (!Number.isSafeInteger(config.username) || config.username <= 0) {
        throw new Error('mobile login payload requires a valid numeric username')
    }
    const payload: Record<string, unknown> = {
        passive: config.passive === true,
        pull: config.pull ?? true,
        product: 0,
        connectType: config.connectType ?? ClientPayload_ConnectType.CELLULAR_UNKNOWN,
        connectReason: config.connectReason ?? ClientPayload_ConnectReason.USER_ACTIVATED,
        userAgent: buildMobileUserAgent(config.deviceProfile),
        username: config.username,
        device: config.device ?? 0,
        lidDbMigrated: config.lidDbMigrated === true,
    }
    if (config.username !== undefined) payload.username = config.username
    if (config.pushName !== undefined) payload.pushName = config.pushName
    if (config.yearClass !== undefined) payload.yearClass = config.yearClass
    if (config.memClass !== undefined) payload.memClass = config.memClass
    return encode('ClientPayload', payload)
}

/**
 * Configuration for the mobile registration payload.
 *
 * A registration payload is sent by a device that has *not* been paired yet,
 * so it carries no username: the server assigns one. Only the Signal
 * identity and the device properties are known at that point.
 */
export interface MobileRegistrationPayloadConfig extends CommonPayloadConfig {
    /** The numeric WhatsApp user id, when it is already known. */
    username?: number
    /** The device id of this device. */
    device?: number
    /** Whether the account has completed the LID database migration. */
    lidDbMigrated?: boolean
    /** Device memory class (Android). */
    memClass?: number
    /** Device year class (Android). */
    yearClass?: number
    /** The Signal registration id of this device. */
    registrationId: number
    /** The 33-byte serialized identity public key. */
    identityKey: Uint8Array
    /** The id of the signed pre-key. */
    signedPreKeyId: number
    /** The 33-byte serialized signed pre-key public key. */
    signedPreKey: Uint8Array
    /** The 64-byte XEdDSA signature over the signed pre-key. */
    signedPreKeySignature: Uint8Array
    /** The encoded `DeviceProps` message. */
    deviceProps?: Uint8Array
}

/**
 * Builds the payload that registers a new device on the **mobile** transport.
 *
 * @param config The payload configuration.
 */
export function buildMobileRegistrationPayload(
    config: MobileRegistrationPayloadConfig,
): Uint8Array {
    if (!Number.isSafeInteger(config.registrationId) || config.registrationId <= 0) {
        throw new Error('mobile registration payload requires a valid registrationId')
    }
    if (!Number.isSafeInteger(config.signedPreKeyId) || config.signedPreKeyId <= 0) {
        throw new Error('mobile registration payload requires a valid signedPreKeyId')
    }
    const versionBase = config.deviceProfile.appVersion ?? DEFAULT_ANDROID_VERSION
    const payload: Record<string, unknown> = {
        passive: config.passive === true,
        pull: config.pull ?? true,
        product: 0,
        connectType: config.connectType ?? ClientPayload_ConnectType.CELLULAR_UNKNOWN,
        connectReason: config.connectReason ?? ClientPayload_ConnectReason.USER_ACTIVATED,
        userAgent: buildMobileUserAgent(config.deviceProfile),
        device: config.device ?? 0,
        lidDbMigrated: config.lidDbMigrated === true,
        devicePairingData: {
            buildHash: md5(utf8(versionBase)),
            deviceProps:
                config.deviceProps ??
                buildDeviceProps(config.deviceProfile, DeviceProps_PlatformType.ANDROID_PHONE),
            eRegid: intToBytes(4, config.registrationId),
            eKeytype: intToBytes(1, 5),
            eIdent: config.identityKey,
            eSkeyId: intToBytes(3, config.signedPreKeyId),
            eSkeyVal: config.signedPreKey,
            eSkeySig: config.signedPreKeySignature,
        },
    }
    if (config.pushName !== undefined) payload.pushName = config.pushName
    return encode('ClientPayload', payload)
}

/**
 * Builds the `DeviceProps` message.
 *
 * `DeviceProps` describes the *host* platform (the machine running the
 * library) and its history-sync capabilities.
 *
 * @param profile The device profile.
 * @param platformType The `PlatformType` enumeration value.
 */
export function buildDeviceProps(
    profile: DeviceProfile,
    platformType: number = DeviceProps_PlatformType.ANDROID_PHONE,
): Uint8Array {
    const version = parseOsVersion(profile.osVersion)
    return encode('DeviceProps', {
        os: profile.os === 'ios' ? 'iOS' : 'Android',
        version,
        platformType,
        requireFullSync: false,
        historySyncConfig: {
            storageQuotaMb: 114149,
            inlineInitialPayloadInE2EeMsg: true,
            supportCallLogHistory: true,
            supportBotUserAgentChatHistory: true,
            supportCagReactionsAndPolls: true,
            supportBizHostedMsg: true,
            supportRecentSyncChunkMessageCountTuning: true,
            supportHostedGroupMsg: true,
            supportFbidBotChatHistory: true,
            supportMessageAssociation: true,
            supportGroupHistory: true,
            thumbnailSyncDaysLimit: 60,
            supportManusHistory: true,
            supportHatchHistory: true,
            supportedBotChannelFbids: [],
        },
    })
}

/**
 * Parses an OS version string into the `DeviceProps.version` tuple.
 *
 * Mirrors WhatsApp Web, which only fills the field when the OS version is a
 * plain dotted-numeric string.
 *
 * @param osVersion The OS version string.
 */
function parseOsVersion(
    osVersion: string,
): { primary: number; secondary?: number; tertiary?: number } | undefined {
    if (!/^[0-9.]+$/.test(osVersion)) return undefined
    const parts = osVersion.split('.')
    const primary = Number.parseInt(parts[0]!, 10)
    if (!Number.isSafeInteger(primary)) return undefined
    const secondary = parts.length > 1 ? Number.parseInt(parts[1]!, 10) : Number.NaN
    const tertiary = parts.length > 2 ? Number.parseInt(parts[2]!, 10) : Number.NaN
    const result: { primary: number; secondary?: number; tertiary?: number } = { primary }
    if (Number.isSafeInteger(secondary)) result.secondary = secondary
    if (Number.isSafeInteger(tertiary)) result.tertiary = tertiary
    return result
}

/** Configuration for the WhatsApp Web login payload. */
export interface WebLoginPayloadConfig {
    /** The numeric WhatsApp user id of the account. */
    username: number
    /** The device id of this device. */
    device?: number
    /** Passive mode. */
    passive?: boolean
    /** Request a full history sync on connect. */
    pull?: boolean
    /** Connect type. */
    connectType?: number
    /** Reason for the connection. */
    connectReason?: number
    /** Push name shown to other users. */
    pushName?: string
    /** The WhatsApp Web version to report. */
    versionBase?: string
    /** The connection attempt counter. */
    connectAttemptCount?: number
    /** Login counter (`lc`). */
    loginCounter?: number
    /** Whether the account has completed the LID database migration. */
    lidDbMigrated?: boolean
}

/**
 * Builds the payload for an existing account on the **WhatsApp Web**
 * transport.
 *
 * @param config The payload configuration.
 */
export function buildLoginPayload(config: WebLoginPayloadConfig): Uint8Array {
    if (!Number.isSafeInteger(config.username) || config.username <= 0) {
        throw new Error('login payload requires a valid numeric username')
    }
    const versionBase = config.versionBase ?? DEFAULT_WEB_VERSION
    const payload: Record<string, unknown> = {
        passive: config.passive === true,
        pull: config.pull ?? true,
        connectType: config.connectType ?? ClientPayload_ConnectType.WIFI_UNKNOWN,
        connectReason: config.connectReason ?? ClientPayload_ConnectReason.USER_ACTIVATED,
        userAgent: buildWebUserAgent(versionBase),
        webInfo: { webSubPlatform: 0 },
        username: config.username,
        device: config.device ?? 0,
        lc: config.loginCounter ?? 0,
        connectAttemptCount: config.connectAttemptCount ?? 0,
        lidDbMigrated: config.lidDbMigrated === true,
    }
    if (config.pushName !== undefined) payload.pushName = config.pushName
    return encode('ClientPayload', payload)
}

/**
 * Configuration for the WhatsApp Web registration payload.
 *
 * A registration payload is sent by a device that has *not* been paired yet,
 * so it carries no username: the server assigns one when the pairing
 * succeeds.
 */
export interface WebRegistrationPayloadConfig
    extends Omit<WebLoginPayloadConfig, 'username'> {
    /** The numeric WhatsApp user id, when it is already known. */
    username?: number
    /** The Signal registration id of this device. */
    registrationId: number
    /** The 33-byte serialized identity public key. */
    identityKey: Uint8Array
    /** The id of the signed pre-key. */
    signedPreKeyId: number
    /** The 33-byte serialized signed pre-key public key. */
    signedPreKey: Uint8Array
    /** The 64-byte XEdDSA signature over the signed pre-key. */
    signedPreKeySignature: Uint8Array
    /** The encoded `DeviceProps` message. */
    deviceProps?: Uint8Array
    /** The browser build hash; defaults to `md5(versionBase)`. */
    buildHash?: Uint8Array
}

/**
 * Builds the payload that registers a new device on the **WhatsApp Web**
 * transport.
 *
 * @param config The payload configuration.
 */
export function buildRegistrationPayload(config: WebRegistrationPayloadConfig): Uint8Array {
    if (!Number.isSafeInteger(config.registrationId) || config.registrationId <= 0) {
        throw new Error('registration payload requires a valid registrationId')
    }
    if (!Number.isSafeInteger(config.signedPreKeyId) || config.signedPreKeyId <= 0) {
        throw new Error('registration payload requires a valid signedPreKeyId')
    }
    const versionBase = config.versionBase ?? DEFAULT_WEB_VERSION
    const payload: Record<string, unknown> = {
        passive: config.passive === true,
        pull: config.pull ?? false,
        connectType: config.connectType ?? ClientPayload_ConnectType.WIFI_UNKNOWN,
        connectReason: config.connectReason ?? ClientPayload_ConnectReason.USER_ACTIVATED,
        userAgent: buildWebUserAgent(versionBase),
        webInfo: { webSubPlatform: 0 },
        devicePairingData: {
            buildHash: config.buildHash ?? md5(utf8(versionBase)),
            deviceProps:
                config.deviceProps ??
                buildDeviceProps(
                    DEFAULT_ANDROID_PROFILE,
                    DeviceProps_PlatformType.DESKTOP,
                ),
            eRegid: intToBytes(4, config.registrationId),
            eKeytype: intToBytes(1, 5),
            eIdent: config.identityKey,
            eSkeyId: intToBytes(3, config.signedPreKeyId),
            eSkeyVal: config.signedPreKey,
            eSkeySig: config.signedPreKeySignature,
        },
    }
    if (config.pushName !== undefined) payload.pushName = config.pushName
    return encode('ClientPayload', payload)
}
