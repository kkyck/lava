#!/usr/bin/env node
/**
 * Size report.
 *
 * Prints the size of the compiled library, broken down per module, so the
 * footprint can be tracked over time. Also verifies the zero-dependency
 * guarantee by checking that the published package declares no runtime
 * dependencies.
 */

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const dist = path.join(root, 'dist')
const src = path.join(root, 'src')

/** Recursively lists every file below a directory. */
function walk(dir) {
    const out = []
    if (!fs.existsSync(dir)) return out
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name)
        if (entry.isDirectory()) out.push(...walk(full))
        else out.push(full)
    }
    return out
}

/** Formats a byte count as a human-readable string. */
function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

/** Sums the size of every file with the given suffix. */
function totalSize(files, suffix) {
    let total = 0
    for (const file of files) {
        if (!file.endsWith(suffix)) continue
        total += fs.statSync(file).size
    }
    return total
}

const distFiles = walk(dist)
const srcFiles = walk(src)

if (distFiles.length === 0) {
    process.stderr.write('dist/ is empty — run `npm run build` first.\n')
    process.exit(1)
}

const jsBytes = totalSize(distFiles, '.js')
const dtsBytes = totalSize(distFiles, '.d.ts')
const srcBytes = totalSize(srcFiles, '.ts')

// Per-directory breakdown of the compiled output.
const groups = new Map()
for (const file of distFiles) {
    if (!file.endsWith('.js')) continue
    const relative = path.relative(dist, file)
    const group = relative.includes(path.sep) ? relative.split(path.sep)[0] : '(root)'
    groups.set(group, (groups.get(group) ?? 0) + fs.statSync(file).size)
}

const lines = []
lines.push('wa-lite size report')
lines.push('='.repeat(46))
lines.push(`compiled javascript  ${formatBytes(jsBytes).padStart(10)}`)
lines.push(`type declarations     ${formatBytes(dtsBytes).padStart(10)}`)
lines.push(`typescript sources   ${formatBytes(srcBytes).padStart(10)}`)
lines.push('')
lines.push('breakdown by module')
lines.push('-'.repeat(46))
const sorted = [...groups.entries()].sort((a, b) => b[1] - a[1])
const width = Math.max(...sorted.map(([name]) => name.length))
for (const [name, size] of sorted) {
    lines.push(`${name.padEnd(width)}  ${formatBytes(size).padStart(10)}`)
}
lines.push('-'.repeat(46))

// The zero-dependency guarantee.
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'))
const runtimeDeps = Object.keys(pkg.dependencies ?? {})
lines.push('')
lines.push(`runtime dependencies ${String(runtimeDeps.length).padStart(10)}`)
for (const dep of runtimeDeps) lines.push(`  - ${dep}`)

const nodeModules = path.join(root, 'node_modules')
const installed = fs.existsSync(nodeModules)
    ? fs.readdirSync(nodeModules).filter((name) => !name.startsWith('.'))
    : []

lines.push('')
lines.push(`installed packages    ${String(installed.length).padStart(10)} (dev only)`)
lines.push('')

process.stdout.write(lines.join('\n'))

if (runtimeDeps.length > 0) {
    process.stderr.write('\nERROR: the package declares runtime dependencies.\n')
    process.exit(1)
}
