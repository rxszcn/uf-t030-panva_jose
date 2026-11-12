import test, { before } from 'node:test'
import assert from 'node:assert/strict'
import * as crypto from 'node:crypto'

import {
  base64url,
  CompactEncrypt,
  compactDecrypt,
  FlattenedEncrypt,
  flattenedDecrypt,
  GeneralEncrypt,
  generalDecrypt,
  errors,
} from '../../src/index.js'
import type * as types from '../../src/types.d.ts'
import { captureRejection, errorLike } from '../_errors.js'

/**
 * Cross-serialization error classification.
 *
 * A caller troubleshooting a failed JWE decryption must be able to tell a malformed token (a
 * structural fault, {@link errors.JWEInvalid} / {@link errors.JOSENotSupported} /
 * {@link errors.JOSEAlgNotAllowed}) apart from a wrong key or failed authentication
 * ({@link errors.JWEDecryptionFailed}), regardless of whether the token arrived in Compact,
 * Flattened, or General JSON Serialization.
 *
 * The distinction is bounded by the side-channel requirements of RFC 7516, Sections 11.4 and 11.5:
 * faults observed only after a recipient's key handling starts stay a JWEDecryptionFailed so a
 * caller cannot learn which recipient their key was meant for.
 */

const context = {} as {
  plaintext: Uint8Array<ArrayBuffer>
  secret: Uint8Array<ArrayBuffer>
  otherSecret: Uint8Array<ArrayBuffer>
  flattened: types.FlattenedJWE
  general: types.GeneralJWE
  generalMulti: types.GeneralJWE
}

before(async () => {
  const encode = TextEncoder.prototype.encode.bind(new TextEncoder())
  context.plaintext = encode('cross-serialization error classification')
  context.secret = crypto.randomFillSync(new Uint8Array(32))
  context.otherSecret = crypto.randomFillSync(new Uint8Array(32))

  context.flattened = await new FlattenedEncrypt(context.plaintext)
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
    .encrypt(context.secret)

  context.general = await new GeneralEncrypt(context.plaintext)
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
    .addRecipient(context.secret)
    .encrypt()

  context.generalMulti = await new GeneralEncrypt(context.plaintext)
    .setProtectedHeader({ enc: 'A256GCM' })
    .addRecipient(context.secret)
    .setUnprotectedHeader({ alg: 'A256GCMKW' })
    .addRecipient(context.otherSecret)
    .setUnprotectedHeader({ alg: 'A256GCMKW' })
    .encrypt()
})

const compactOf = (flattened: types.FlattenedJWE): string =>
  [
    flattened.protected ?? '',
    flattened.encrypted_key ?? '',
    flattened.iv ?? '',
    flattened.ciphertext,
    flattened.tag ?? '',
  ].join('.')

// Flip a bit inside the decoded value while keeping a valid base64url encoding, so the result is a
// well-formed token that fails authentication rather than a structurally malformed one.
const tamperEncoded = (value: string): string => {
  const decoded = base64url.decode(value)
  decoded[0] = decoded[0] ^ 0xff
  return base64url.encode(decoded)
}

test('authentication failures are indistinguishable across every serialization', async () => {
  // A wrong key and a tampered authentication tag both fail authentication, never structure.
  const tamperedCompact = compactOf({
    ...context.flattened,
    tag: tamperEncoded(context.flattened.tag!),
  })
  const tamperedFlattened = { ...context.flattened, tag: tamperEncoded(context.flattened.tag!) }
  const tamperedGeneral = { ...context.general, tag: tamperEncoded(context.general.tag!) }
  const tamperedMulti = { ...context.generalMulti, tag: tamperEncoded(context.generalMulti.tag!) }

  for (const [label, block] of [
    ['compact, wrong key', () => compactDecrypt(compactOf(context.flattened), context.otherSecret)],
    ['flattened, wrong key', () => flattenedDecrypt(context.flattened, context.otherSecret)],
    ['general, wrong key', () => generalDecrypt(context.general, context.otherSecret)],
    [
      'general multi-recipient, key for neither recipient',
      () => generalDecrypt(context.generalMulti, crypto.randomFillSync(new Uint8Array(32))),
    ],
    ['compact, tampered tag', () => compactDecrypt(tamperedCompact, context.secret)],
    ['flattened, tampered tag', () => flattenedDecrypt(tamperedFlattened, context.secret)],
    ['general, tampered tag', () => generalDecrypt(tamperedGeneral, context.secret)],
    [
      'general multi-recipient, tampered shared tag',
      () => generalDecrypt(tamperedMulti, context.secret),
    ],
  ] as const) {
    await assert.rejects(
      block,
      errorLike({
        code: 'ERR_JWE_DECRYPTION_FAILED',
        message: 'decryption operation failed',
      }),
      label,
    )
  }
})

test('a malformed protected header is a structural fault in every serialization', async () => {
  const malformedProtected = 'not-base64url-json'

  const compact = compactOf({ ...context.flattened, protected: malformedProtected })
  const flattened = { ...context.flattened, protected: malformedProtected }
  const general = { ...context.general, protected: malformedProtected }
  const generalMulti = { ...context.generalMulti, protected: malformedProtected }

  const cases = [
    () => compactDecrypt(compact, context.secret),
    () => flattenedDecrypt(flattened, context.secret),
    () => generalDecrypt(general, context.secret),
    () => generalDecrypt(generalMulti, context.secret),
  ]

  for (const decrypt of cases) {
    const error = await captureRejection(decrypt, errorLike({ code: 'ERR_JWE_INVALID' }))
    assert.ok(error instanceof errors.JWEInvalid)
  }
})

test('a malformed shared ciphertext is a structural fault in every serialization', async () => {
  const malformedCiphertext = '!'

  const compact = compactOf({ ...context.flattened, ciphertext: malformedCiphertext })
  const flattened = { ...context.flattened, ciphertext: malformedCiphertext }
  const general = { ...context.general, ciphertext: malformedCiphertext }
  const generalMulti = { ...context.generalMulti, ciphertext: malformedCiphertext }

  for (const decrypt of [
    () => compactDecrypt(compact, context.secret),
    () => flattenedDecrypt(flattened, context.secret),
    () => generalDecrypt(general, context.secret),
    () => generalDecrypt(generalMulti, context.secret),
  ]) {
    await assert.rejects(decrypt, errorLike({ code: 'ERR_JWE_INVALID' }))
  }
})

test('a missing content-encryption algorithm is a structural fault in every serialization', async () => {
  // Drop "enc" from the protected header; the token shape is otherwise intact.
  const protectedHeader = base64url.encode(JSON.stringify({ alg: 'dir' }))

  const compact = compactOf({ ...context.flattened, protected: protectedHeader })
  const flattened = { ...context.flattened, protected: protectedHeader }
  const general = { ...context.general, protected: protectedHeader }

  for (const decrypt of [
    () => compactDecrypt(compact, context.secret),
    () => flattenedDecrypt(flattened, context.secret),
    () => generalDecrypt(general, context.secret),
  ]) {
    await assert.rejects(
      decrypt,
      errorLike({
        code: 'ERR_JWE_INVALID',
        message: 'missing JWE Encryption Algorithm (enc) in JWE Header',
      }),
    )
  }
})

test('a disallowed algorithm is a policy fault, not an authentication failure', async () => {
  // The token is well formed; the caller's own options reject its algorithm.
  const options = { keyManagementAlgorithms: ['A256KW'] } as types.DecryptOptions

  await assert.rejects(
    flattenedDecrypt(context.flattened, context.secret, options),
    errorLike({ code: 'ERR_JOSE_ALG_NOT_ALLOWED' }),
  )
  await assert.rejects(
    generalDecrypt(context.general, context.secret, options),
    errorLike({ code: 'ERR_JOSE_ALG_NOT_ALLOWED' }),
  )
})

test('General JWE reports a structural fault when no recipient reaches key handling', async () => {
  // Every recipient lacks an alg, so none can even attempt key handling. The structural fault is
  // reported instead of a misleading decryption failure.
  const jwe = {
    ...context.generalMulti,
    recipients: [{}, {}],
  }

  await assert.rejects(
    generalDecrypt(jwe, context.secret),
    errorLike({
      code: 'ERR_JWE_INVALID',
      message: 'missing JWE Algorithm (alg) in JWE Header',
    }),
  )
})

test('General JWE collapses a recipient-local structural fault once another recipient authenticates', async () => {
  // The first recipient is structurally malformed; the second is a valid recipient that the
  // caller's key cannot authenticate. Surfacing the first recipient's shape would reveal the key
  // was meant for the second, so the overall result stays a decryption failure.
  const jwe = {
    ...context.generalMulti,
    recipients: [{}, context.generalMulti.recipients[1]],
  }

  // The caller holds the first recipient's secret, which cannot unlock the second recipient.
  await assert.rejects(
    generalDecrypt(jwe, context.secret),
    errorLike({ code: 'ERR_JWE_DECRYPTION_FAILED' }),
  )

  // A successful recipient still wins regardless of another recipient's malformed shape.
  const successFirst = {
    ...context.generalMulti,
    recipients: [context.generalMulti.recipients[0], {}],
  }
  await assert.doesNotReject(generalDecrypt(successFirst, context.secret))
})

test('General JWE collapses post-key-handling structural errors to protect recipient privacy', async () => {
  // A malformed AES-GCMKW key-management tag is detected while unwrapping a recipient's key, i.e.
  // after key handling for that recipient began. Reporting it as structural would distinguish a
  // matching recipient (unwrapping attempted) from a non-matching one, so it must collapse.
  const jwe = structuredClone(context.generalMulti)
  const recipient = jwe.recipients[0]
  const tag = base64url.decode(recipient.header!.tag!)
  recipient.header!.tag = base64url.encode(tag.subarray(0, -1))

  await assert.rejects(
    generalDecrypt(jwe, context.secret),
    errorLike({ code: 'ERR_JWE_DECRYPTION_FAILED' }),
  )

  // The same malformed key-management tag keeps its structural code in the single-recipient
  // Flattened serialization, where there is no other recipient to distinguish.
  const flattened = await new FlattenedEncrypt(context.plaintext)
    .setProtectedHeader({ alg: 'A256GCMKW', enc: 'A256GCM' })
    .encrypt(context.secret)
  const flattenedHeader = JSON.parse(
    new TextDecoder().decode(base64url.decode(flattened.protected!)),
  )
  const flattenedTag = base64url.decode(flattenedHeader.tag)
  flattenedHeader.tag = base64url.encode(flattenedTag.subarray(0, -1))
  flattened.protected = base64url.encode(JSON.stringify(flattenedHeader))

  await assert.rejects(
    flattenedDecrypt(flattened, context.secret),
    errorLike({ code: 'ERR_JWE_INVALID' }),
  )
})

test('an empty protected member is structural, never a decryption failure', async () => {
  const flattened = { ...context.flattened, protected: '' }
  const general = { ...context.general, protected: '' }

  await assert.rejects(
    flattenedDecrypt(flattened, context.secret),
    errorLike({ code: 'ERR_JWE_INVALID' }),
  )
  await assert.rejects(
    generalDecrypt(general, context.secret),
    errorLike({ code: 'ERR_JWE_INVALID' }),
  )
})

test('structural and authentication errors are separable by instanceof as well as code', async () => {
  const structural = generalDecrypt({ ...context.general, protected: '!' }, context.secret).catch(
    (error) => error,
  )
  const authentication = generalDecrypt(context.general, context.otherSecret).catch(
    (error) => error,
  )

  const [structuralError, authenticationError] = await Promise.all([structural, authentication])

  assert.ok(structuralError instanceof errors.JWEInvalid)
  assert.ok(!(structuralError instanceof errors.JWEDecryptionFailed))
  assert.ok(authenticationError instanceof errors.JWEDecryptionFailed)
  assert.ok(!(authenticationError instanceof errors.JWEInvalid))
})
