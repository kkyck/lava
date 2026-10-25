/**
 * WhatsApp WAP dictionary tokens.
 *
 * The token tables now live in `./constants.js` next to the token constants
 * they belong to. This module only re-exports them so that existing imports
 * of `./tokens.js` keep working.
 */

export {
    DICT_VERSION,
    DICTIONARIES,
    DICTIONARY_0_TOKENS,
    DICTIONARY_1_TOKENS,
    DICTIONARY_2_TOKENS,
    DICTIONARY_3_TOKENS,
    SINGLE_BYTE_TOKENS,
} from './constants.js'
