/**
 * A minimal logger.
 *
 * The library never logs anything by itself; it forwards every diagnostic to
 * the sink the user provides. The default sink writes to `stderr`, so a
 * misbehaving library can never corrupt the protocol stream on `stdout`.
 */

/** The log levels the library uses. */
export const WA_LOG_LEVELS = Object.freeze([
    'trace',
    'debug',
    'info',
    'warn',
    'error',
    'silent',
] as const)

/** A log level. */
export type WaLogLevel = (typeof WA_LOG_LEVELS)[number]

/** The numeric severity of each level. */
const LEVEL_WEIGHT: Record<WaLogLevel, number> = {
    trace: 10,
    debug: 20,
    info: 30,
    warn: 40,
    error: 50,
    silent: 100,
}

/** A structured log record. */
export interface WaLogRecord {
    /** The log level. */
    level: WaLogLevel
    /** The message. */
    message: string
    /** Additional structured fields. */
    fields?: Record<string, unknown>
}

/** A log sink. */
export interface WaLogger {
    /**
     * Writes a log record.
     *
     * @param record The record to write.
     */
    log(record: WaLogRecord): void
}

/** The options of the default logger. */
export interface ConsoleLoggerOptions {
    /** The minimum level that is written. */
    level?: WaLogLevel
    /** A label prefixed to every message. */
    scope?: string
    /** Where the output goes; defaults to `stderr`. */
    write?: (line: string) => void
}

/**
 * Creates a logger that writes to `stderr`.
 *
 * @param options The logger options.
 */
export function createConsoleLogger(options: ConsoleLoggerOptions = {}): WaLogger {
    const level = options.level ?? 'info'
    const threshold = LEVEL_WEIGHT[level]
    const write = options.write ?? ((line: string) => process.stderr.write(line))
    const scope = options.scope ? `[${options.scope}] ` : ''
    return {
        log(record) {
            if (LEVEL_WEIGHT[record.level] < threshold) return
            const fields = record.fields
                ? ` ${JSON.stringify(record.fields)}`
                : ''
            write(`${scope}${record.level.toUpperCase()} ${record.message}${fields}\n`)
        },
    }
}

/**
 * Creates a logger that discards everything.
 */
export function createSilentLogger(): WaLogger {
    return { log: () => {} }
}

/**
 * Returns a logger that prefixes every record with a scope.
 *
 * @param logger The parent logger.
 * @param scope The scope label.
 */
export function childLogger(logger: WaLogger, scope: string): WaLogger {
    return {
        log(record) {
            logger.log({ ...record, fields: { ...(record.fields ?? {}), scope } })
        },
    }
}
