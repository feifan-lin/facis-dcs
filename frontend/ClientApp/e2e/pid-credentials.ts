import path from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..')

/** Pre-issued EUDI PID SD-JWTs (OID4VCI). Override for kind CI after live issuance. */
export const E2E_PID_JWT_A =
  process.env.E2E_PID_JWT_A?.trim() || path.join(repoRoot, 'testWallet/credentials/johndoe.pid.jwt')

export const E2E_PID_JWT_B =
  process.env.E2E_PID_JWT_B?.trim() || path.join(repoRoot, 'testWallet/credentials/janesmith.pid.jwt')
