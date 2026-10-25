/**
 * Facts about the host the client runs on.
 *
 * The linking protocol announces the program that links and the system it
 * runs on, so the client needs to know the name of the operating system it
 * is started on. Only Node's own modules are used, so the library stays free
 * of runtime dependencies.
 */

import { platform } from 'node:os'

/**
 * The name of the operating system the client runs on.
 *
 * The name is the one the official client uses, e.g. `Windows` for the
 * Windows builds of the desktop app.
 *
 * @returns The name of the operating system.
 */
export function hostOsName(): string {
    switch (platform()) {
        case 'win32':
            return 'Windows'
        case 'darwin':
            return 'macOS'
        case 'linux':
            return 'Linux'
        case 'freebsd':
            return 'FreeBSD'
        case 'openbsd':
            return 'OpenBSD'
        default:
            return 'Unknown'
    }
}
