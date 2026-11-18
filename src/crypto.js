import crypto from 'node:crypto';

/**
 * All proof material is derived from a per-tenant key. Two properties matter:
 *
 *  1. Audit evidence must not leak erased detail. We therefore never store the
 *     plaintext subject identifier or the payload in proofs. Instead we store
 *     keyed commitments H_k(canonical content). Without the key a commitment
 *     cannot be brute-forced against a candidate list (the key is a secret
 *     pepper), so a leaked proof bundle reveals only "some object with this
 *     opaque ref existed".
 *  2. Evidence must be independently re-checkable *given* the key, so the
 *     proof bundle carries leaf commitments + Merkle paths, and verification is
 *     re-run over the same canonical content.
 */

export function deriveKey(masterSecret, tenantId, purpose) {
  return crypto
    .createHmac('sha256', masterSecret)
    .update(`${purpose}\u0000${tenantId}`)
    .digest('hex');
}

export function hmacHex(keyHex, message) {
  return crypto.createHmac('sha256', Buffer.from(keyHex, 'hex')).update(message).digest('hex');
}

export function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

/** Operational key -> stable pseudonymous token used by fences and audit. */
export function subjectToken(keyHex, subjectRef) {
  return 'sub_' + hmacHex(keyHex, `subject\u0000${String(subjectRef).trim().toLowerCase()}`).slice(0, 32);
}

/** One-way fingerprint of a key, safe to display. */
export function keyFingerprint(keyHex) {
  return 'kfp_' + sha256Hex(`fingerprint\u0000${keyHex}`).slice(0, 16);
}

/**
 * Deterministic JSON serialisation: sorted object keys, no whitespace. The
 * same canonicalisation is used when committing and when verifying, so a
 * proof rebuilt from storage hashes identically.
 */
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
}

// --- Merkle tree --------------------------------------------------------------
// Domain-separated, sorted-pair hashing: leaf = H(0x00 || commitment),
// node = H(0x01 || min(a,b) || max(a,b)). Sorting pairs makes the tree
// independent of leaf ordering and blocks second-preimage/duplicate tricks.
// Odd nodes promote unchanged to the next level.

function hashLeaf(commitment) {
  return sha256Hex(Buffer.concat([Buffer.from([0x00]), Buffer.from(commitment, 'utf8')]));
}

function hashNode(a, b) {
  const [x, y] = a <= b ? [a, b] : [b, a];
  return sha256Hex(Buffer.concat([Buffer.from([0x01]), Buffer.from(x, 'utf8'), Buffer.from(y, 'utf8')]));
}

export function merkleRoot(commitments) {
  if (commitments.length === 0) return sha256Hex('empty-tree');
  let level = commitments.map(hashLeaf);
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? hashNode(level[i], level[i + 1]) : level[i]);
    }
    level = next;
  }
  return level[0];
}

export function merkleProof(commitments, index) {
  if (index < 0 || index >= commitments.length) throw new Error('leaf index out of range');
  let level = commitments.map(hashLeaf);
  let idx = index;
  const path = [];
  while (level.length > 1) {
    const sibling = idx % 2 === 0 ? idx + 1 : idx - 1;
    if (sibling < level.length) {
      path.push({ position: idx % 2 === 0 ? 'right' : 'left', hash: level[sibling] });
    }
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? hashNode(level[i], level[i + 1]) : level[i]);
    }
    level = next;
    idx = Math.floor(idx / 2);
  }
  return { leafHash: hashLeaf(commitments[index]), path, root: level[0] };
}

export function verifyMerkleProof(proof) {
  let acc = proof.leafHash;
  for (const step of proof.path) {
    acc = step.position === 'right' ? hashNode(acc, step.hash) : hashNode(step.hash, acc);
  }
  return acc === proof.root;
}

/**
 * Content commitment for one erased object. The commitment binds the layer,
 * the opaque object ref, and a digest of the content that was removed. The
 * `contentDigest` is itself a keyed HMAC, so the raw values never appear.
 */
export function contentCommitment(keyHex, { layer, objectRef, contentDigest }) {
  return 'cm_' + hmacHex(keyHex, `content\u0000${layer}\u0000${objectRef}\u0000${contentDigest}`).slice(0, 40);
}

export function contentDigest(keyHex, canonicalContent) {
  return hmacHex(keyHex, `digest\u0000${canonicalContent}`);
}

/**
 * The proof document is hashed over its canonical form excluding the hash
 * field itself, producing a stable integrity value that can be re-derived.
 */
export function proofHash(proofBody) {
  const { proofHash: _omit, ...rest } = proofBody;
  return sha256Hex(canonicalJson(rest));
}

export function sha256Bytes(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}
