/**
 * Protocol-wide constants: node tags, stanza types and tuning defaults.
 */

/** Node tags used across the protocol. */
export const WA_NODE_TAGS = Object.freeze({
    IQ: 'iq',
    SYNC: 'sync',
    COLLECTION: 'collection',
    PATCH: 'patch',
    PATCHES: 'patches',
    SNAPSHOT: 'snapshot',
    ERROR: 'error',
    ACK: 'ack',
    NOTIFICATION: 'notification',
    SUCCESS: 'success',
    FAILURE: 'failure',
    INFO_BULLETIN: 'ib',
    OFFLINE: 'offline',
    DIRTY: 'dirty',
    EDGE_ROUTING: 'edge_routing',
    ROUTING_INFO: 'routing_info',
    MEDIA_CONN: 'media_conn',
    HOST: 'host',
    USYNC: 'usync',
    QUERY: 'query',
    DEVICES: 'devices',
    DEVICE: 'device',
    DIGEST: 'digest',
    KEY_FETCH: 'key_fetch',
    LIST: 'list',
    USER: 'user',
    CONTACT: 'contact',
    LID: 'lid',
    PICTURE: 'picture',
    PRIVACY: 'privacy',
    PARTICIPATING: 'participating',
    PARTICIPANTS: 'participants',
    DESCRIPTION: 'description',
    MY_ADDONS: 'my_addons',
    KEY: 'key',
    OP: 'op',
    REGISTRATION: 'registration',
    TYPE: 'type',
    IDENTITY: 'identity',
    SKEY: 'skey',
    RETRY: 'retry',
    KEYS: 'keys',
    ID: 'id',
    REF: 'ref',
    VALUE: 'value',
    SIGNATURE: 'signature',
    HASH: 'hash',
    ROTATE: 'rotate',
    PAIR_DEVICE: 'pair-device',
    PAIR_SUCCESS: 'pair-success',
    LINK_CODE_COMPANION_REG: 'link_code_companion_reg',
    LINK_CODE_PAIRING_REF: 'link_code_pairing_ref',
    COUNTRY_CODE: 'country_code',
    DEVICE_IDENTITY: 'device-identity',
    PLATFORM: 'platform',
    PASSKEY_REQUEST_OPTIONS: 'passkey_request_options',
    PRIMARY_EPHEMERAL_IDENTITY: 'primary_ephemeral_identity',
    SUBJECT: 'subject',
    BODY: 'body',
    PARTICIPANT: 'participant',
    INVITE: 'invite',
    LEAVE: 'leave',
    GROUP: 'group',
    LOCKED: 'locked',
    UNLOCKED: 'unlocked',
    ANNOUNCEMENT: 'announcement',
    EPHEMERAL: 'ephemeral',
    MEMBERSHIP_APPROVAL_MODE: 'membership_approval_mode',
    GROUP_JOIN: 'group_join',
    ABPROPS: 'abprops',
    PROPS: 'props',
    PLAINTEXT: 'plaintext',
    PRESENCE: 'presence',
    PUSHNAME: 'pushname',
    CHATSTATE: 'chatstate',
    CALL: 'call',
    COMPOSING: 'composing',
    PAUSED: 'paused',
    BIZ: 'biz',
    INTERACTIVE: 'interactive',
    NATIVE_FLOW: 'native_flow',
    BOT: 'bot',
    META: 'meta',
    STATUS: 'status',
    USERNAME: 'username',
    TEXT_STATUS: 'text_status',
    DISAPPEARING_MODE: 'disappearing_mode',
    BUSINESS: 'business',
    PUB_KEY: 'pub-key',
    KEY_INDEX_LIST: 'key-index-list',
    CLIENT_PROPS: 'client-props',
    PEM: 'pem',
    TTL: 'ttl',
    KEY_ID: 'key_id',
    REMOVE_COMPANION_DEVICE: 'remove-companion-device',
    PRIMARY_IDENTITY_PUB: 'primary_identity_pub',
    COMPANION_IDENTITY_PUBLIC: 'companion_identity_public',
    COMPANION_SERVER_AUTH_KEY_PUB: 'companion_server_auth_key_pub',
    LINK_CODE_PAIRING_WRAPPED_PRIMARY_EPHEMERAL_PUB:
        'link_code_pairing_wrapped_primary_ephemeral_pub',
    LINK_CODE_PAIRING_WRAPPED_COMPANION_EPHEMERAL_PUB:
        'link_code_pairing_wrapped_companion_ephemeral_pub',
    LINK_CODE_PAIRING_WRAPPED_KEY_BUNDLE: 'link_code_pairing_wrapped_key_bundle',
    COUNT: 'count',
} as const)

/** IQ stanza types. */
export const WA_IQ_TYPES = Object.freeze({
    GET: 'get',
    SET: 'set',
    RESULT: 'result',
    ERROR: 'error',
} as const)

/**
 * `<notification type>` values.
 *
 * The `encrypt` notification carries the Signal housekeeping stanzas: the
 * `<count/>` child means the server is running out of our pre-keys, the
 * `<digest/>` child means the key digest has to be re-validated.
 */
export const WA_NOTIFICATION_TYPES = Object.freeze({
    ENCRYPT: 'encrypt',
} as const)

/** XML namespaces used by the protocol. */
export const WA_XMLNS = Object.freeze({
    MD: 'md',
    APP_STATE_SYNC: 'w:sync:app:state',
    MEDIA: 'w:m',
    SIGNAL: 'encrypt',
    DIRTY_BITS: 'urn:xmpp:whatsapp:dirty',
    PROFILE_PICTURE: 'w:profile:picture',
    PRIVACY: 'privacy',
    BLOCKLIST: 'blocklist',
    USYNC: 'usync',
    BUSINESS: 'w:biz',
    STATUS: 'status',
    GROUPS: 'w:g2',
    NEWSLETTER: 'newsletter',
    TOS: 'tos',
    XMPP_PING: 'urn:xmpp:ping',
    WHATSAPP_PING: 'w:p',
    ABPROPS: 'abt',
    MEX: 'w:mex',
    BOT: 'bot',
    DISAPPEARING_MODE: 'disappearing_mode',
    PASSIVE: 'passive',
} as const)

/** Message-related node tags. */
export const WA_MESSAGE_TAGS = Object.freeze({
    MESSAGE: 'message',
    ENC: 'enc',
    RECEIPT: 'receipt',
    ACK: 'ack',
    ERROR: 'error',
} as const)

/** `<enc type>` ciphertext kinds. */
export const WA_ENC_CIPHERTEXT_TYPES = Object.freeze({
    MESSAGE: 'msg',
    PREKEY: 'pkmsg',
    SENDER_KEY: 'skmsg',
    MESSAGE_SECRET: 'msmsg',
} as const)

/** `addressing_mode` stanza attribute values. */
export const WA_ADDRESSING_MODES = Object.freeze({
    PN: 'pn',
    LID: 'lid',
} as const)

/** Message stanza types and receipt types. */
export const WA_MESSAGE_TYPES = Object.freeze({
    ENC_VERSION: '2',
    MEDIA_NOTIFY: 'medianotify',
    ACK_TYPE_ERROR: 'error',
    ACK_CLASS_ERROR: 'error',
    ACK_CLASS_MESSAGE: 'message',
    ACK_CLASS_CALL: 'call',
    RECEIPT_TYPE_DELIVERY: 'delivery',
    RECEIPT_TYPE_SENDER: 'sender',
    RECEIPT_TYPE_INACTIVE: 'inactive',
    RECEIPT_TYPE_READ: 'read',
    RECEIPT_TYPE_READ_SELF: 'read-self',
    RECEIPT_TYPE_PLAYED: 'played',
    RECEIPT_TYPE_PLAYED_SELF: 'played-self',
    RECEIPT_TYPE_HISTORY_SYNC: 'hist_sync',
    RECEIPT_TYPE_PEER: 'peer_msg',
    RECEIPT_TYPE_SERVER_ERROR: 'server-error',
    RECEIPT_TYPE_RETRY: 'retry',
    RECEIPT_TYPE_ENC_REKEY_RETRY: 'enc_rekey_retry',
    RECEIPT_TYPE_VIEW: 'view',
} as const)

/** Stanza types used by the `<message>` node. */
export const WA_STANZA_MSG_TYPES = Object.freeze({
    TEXT: 'text',
    MEDIA: 'media',
    MEDIA_NOTIFY: 'medianotify',
    PAY: 'pay',
    POLL: 'poll',
    REACTION: 'reaction',
    EVENT: 'event',
} as const)

/** Media types carried in the `mediatype` attribute. */
export const WA_ENC_MEDIA_TYPES = Object.freeze({
    IMAGE: 'image',
    VIDEO: 'video',
    PTV: 'ptv',
    AUDIO: 'audio',
    PTT: 'ptt',
    LOCATION: 'location',
    LIVE_LOCATION: 'livelocation',
    VCARD: 'vcard',
    CONTACT_ARRAY: 'contact_array',
    DOCUMENT: 'document',
    URL: 'url',
    GIF: 'gif',
    STICKER: 'sticker',
    STICKER_PACK: 'sticker_pack',
    LIST: 'list',
    LIST_RESPONSE: 'list_response',
    BUTTON: 'button',
    BUTTON_RESPONSE: 'buttons_response',
    ORDER: 'order',
    PRODUCT: 'product',
    NATIVE_FLOW_RESPONSE: 'native_flow_response',
    GROUP_HISTORY: 'group_history',
} as const)

/** Call payload tags. */
export const WA_CALL_PAYLOAD_TAGS = Object.freeze({
    OFFER: 'offer',
    OFFER_NOTICE: 'offer_notice',
    ACCEPT: 'accept',
    PREACCEPT: 'preaccept',
    REJECT: 'reject',
    TERMINATE: 'terminate',
    TRANSPORT: 'transport',
    MUTE: 'mute',
    VIDEO_STATE: 'video_state',
    GROUP_INFO: 'group_info',
    GROUP_UPDATE: 'group_update',
    ENC_REKEY: 'enc_rekey',
    PEER_STATE: 'peer_state',
    FLOW_CONTROL: 'flow_control',
    WEB_CLIENT: 'web_client',
} as const)

/** The children a call payload carries. */
export const WA_CALL_CHILD_TAGS = Object.freeze({
    VIDEO: 'video',
    SILENCE: 'silence',
    GROUP_INFO: 'group_info',
} as const)

/** Call stanza attributes. */
export const WA_CALL_NODE_ATTRS = Object.freeze({
    CALL_ID: 'call-id',
    CALL_CREATOR: 'call-creator',
    GROUP_JID: 'group-jid',
    CALLER_PN: 'caller_pn',
    CALLER_COUNTRY_CODE: 'caller_country_code',
    USERNAME: 'username',
    NOTIFY: 'notify',
    SENDER_LID: 'sender_lid',
    PLATFORM: 'platform',
    VERSION: 'version',
    REASON: 'reason',
    USER_PN: 'user_pn',
    GUEST_NAME: 'guest_name',
} as const)

/** Presence values. */
export const WA_PRESENCE_TYPES = Object.freeze({
    AVAILABLE: 'available',
    UNAVAILABLE: 'unavailable',
    COMPOSING: 'composing',
    RECORDING: 'recording',
    PAUSED: 'paused',
} as const)

/** Chat-state values. */
export const WA_CHATSTATE_MEDIA = Object.freeze({
    TEXT: 'text',
} as const)

/** Privacy categories, as used by the `privacy` node. */
export const WA_PRIVACY_VALUES = Object.freeze({
    ALL: 'all',
    NONE: 'none',
    CONTACTS: 'contacts',
    CONTACT_BLACKLIST: 'contact_blacklist',
    MATCH_LAST_SEEN: 'match_last_seen',
    APPROVAL: 'approval',
} as const)

/** Privacy list actions. */
export const WA_PRIVACY_LIST_ACTIONS = Object.freeze({
    ADD: 'add',
    REMOVE: 'remove',
} as const)

/** Default socket URLs for the WhatsApp Web transport. */
export const CHAT_SOCKET_URLS: readonly string[] = Object.freeze([
    'wss://web.whatsapp.com/ws/chat',
    'wss://web.whatsapp.com:5222/ws/chat',
])

/** Default endpoint for the WhatsApp mobile (WAP) transport. */
export const MOBILE_TCP_ENDPOINT = 'tcp://g.whatsapp.net:443'

/** Tuning defaults shared across the library. */
export const WA_DEFAULTS = Object.freeze({
    /** The server that handles account-level requests. */
    HOST_DOMAIN: 's.whatsapp.net',
    /** The server that handles group requests. */
    GROUP_SERVER: 'g.us',
    /** Timeout for an IQ request/response round trip. */
    IQ_TIMEOUT_MS: 15000,
    /** Timeout for a generic node query. */
    NODE_QUERY_TIMEOUT_MS: 15000,
    /** Timeout for the Noise handshake. */
    CONNECT_TIMEOUT_MS: 10000,
    /** Timeout for socket inactivity. */
    SOCKET_TIMEOUT_MS: 10000,
    /** Delay before reconnecting. */
    RECONNECT_INTERVAL_MS: 2000,
    /** Interval between health checks. */
    HEALTH_CHECK_INTERVAL_MS: 15000,
    /** How long a socket may stay silent before it is considered dead. */
    DEAD_SOCKET_TIMEOUT_MS: 20000,
    /** Timeout for media uploads. */
    MEDIA_TIMEOUT_MS: 30000,
    /** Timeout for pre-key bundle fetches. */
    SIGNAL_FETCH_KEY_BUNDLES_TIMEOUT_MS: 20000,
    /** Timeout for a message ack. */
    MESSAGE_ACK_TIMEOUT_MS: 10000,
    /** Maximum send attempts for a single message. */
    MESSAGE_MAX_ATTEMPTS: 3,
    /** Delay between message retries. */
    MESSAGE_RETRY_DELAY_MS: 750,
    /** Maximum age of a pairing code, in seconds. */
    PAIRING_CODE_MAX_AGE_SECONDS: 180,
    /** Initial QR code TTL, in milliseconds. */
    QR_INITIAL_TTL_MS: 60000,
    /** QR code rotation interval, in milliseconds. */
    QR_ROTATION_TTL_MS: 20000,
    /** Maximum number of dangling receipts kept in memory. */
    MAX_DANGLING_RECEIPTS: 2048,
})
