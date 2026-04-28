/**
 * Cardano UTxO ledger validation — Conway/Babbage era.
 *
 * Formal reference: SL-D5 "A Formal Specification of the Cardano Ledger
 * supporting the Babbage Era" + Conway Ledger Specification.
 *
 * Rule set implemented (all required for a non-script UTxO transaction):
 *
 *  UTxO rules (UTXO):
 *   U1  inputs ≠ ∅
 *   U2  inputs ⊆ dom(utxo)  — no phantom inputs
 *   U3  no duplicate inputs within the tx
 *   U4  current_slot ≤ ttl                (if ttl present)
 *   U5  validity_start ≤ current_slot     (if validity_start present)
 *   U6  size(tx) ≤ maxTxSize
 *   U7  ∀ o ∈ outputs: lovelace(o) ≥ 0
 *   U8  ∀ o ∈ outputs: lovelace(o) ≥ minAda(pp, o)
 *        Conway formula: minADA = coinsPerUTxOByte × (160 + |serialise(o)|)
 *   U9  fee ≥ minFee(pp, tx) = minFeeA × |tx| + minFeeB
 *   U10 Σ value(inputs) + mint = Σ value(outputs) + fee
 *        (basic txs have mint = ∅, so consumed = produced + fee)
 *
 *  Witness rules (UTXOW):
 *   W1  ∀ (vkey, sig) ∈ vkeyWitnesses:
 *         ed25519_verify(vkey, blake2b256(CBOR(txBody)), sig) = true
 *   W2  ∀ key-locked input:
 *         ∃ witness where blake2b224(vkey) = paymentKeyHash(address)
 *   W3  ∀ kh ∈ body.required_signers:
 *         ∃ witness where blake2b224(vkey) = kh
 *         (cardano-ledger: witsVKeyNeeded includes reqSignerHashes)
 *
 *  Network rules (LEDGER):
 *   N1  body.network_id, if present, must equal protocol network id
 *         (cardano-ledger: validateNetworkId)
 *   N2  every output's address must be on the protocol network
 *         (cardano-ledger: validateOutputAddrAttrsTooBig + validateNetworkId)
 *
 * Plutus scripts, staking, withdrawals and minting policy checks are
 * intentionally deferred — the devnet handles basic UTxO transactions first.
 *
 * Parsing delegates to @harmoniclabs/cardano-ledger-ts (Tx.fromCbor)
 * which handles all CBOR edge cases (tag-258 sets, era variants, etc.).
 * Signature verification uses @noble/ed25519 (RFC 8032 standard).
 */

import {
  Tx as LedgerTx,
  Address,
  Value as LedgerValue,
} from '@harmoniclabs/cardano-ledger-ts';
import cbor from 'cbor';

import { verifyEd25519, toHex, fromHex, blake2b224 } from '../crypto.js';
import type { Transaction, TxInput, TxOutput, UTxO, VKeyWitness, Value, MultiAsset } from '../types.js';
import type { LedgerState } from './state.js';
import type { ProtocolParams } from '../config.js';
import { NETWORK_ID } from '../config.js';

// ── Public API ────────────────────────────────────────────────────────────────

export type ValidationOk    = { ok: true };
export type ValidationError = { ok: false; error: string };
export type ValidationResult = ValidationOk | ValidationError;

export class TransactionValidator {
  constructor(
    private readonly state:  LedgerState,
    private readonly params: ProtocolParams,
  ) {}

  /**
   * Parse the raw CBOR bytes into our internal Transaction type,
   * then run all ledger rules.
   *
   * @param rawCbor  Raw transaction bytes (binary CBOR, not hex)
   * @returns        Parsed transaction (if valid) or a structured error
   */
  parseAndValidate(
    rawCbor: Uint8Array,
  ): { ok: true; tx: Transaction } | { ok: false; error: string } {
    // ── Parse via cardano-ledger-ts ────────────────────────────────────────
    // The harmonic Conway parser rejects valid aux-data shapes that omit some
    // optional script fields (e.g. an empty Tag 259 map produced by Mesh).
    // We normalise position 3 (auxiliary_data) to null on parse failure so
    // every other validation rule still runs. The transaction body bytes
    // (which carry the body hash and signatures) are never touched.
    const normalisedCbor = normaliseTxCbor(rawCbor);

    let ledgerTx: LedgerTx;
    try {
      ledgerTx = LedgerTx.fromCbor(toHex(normalisedCbor));
    } catch (e) {
      return err(`CBOR parse error: ${(e as Error).message}`);
    }

    // Convert to our internal representation
    let tx: Transaction;
    try {
      tx = ledgerTxToInternal(ledgerTx, this.state.currentSlot());
    } catch (e) {
      return err(`Transaction structure error: ${(e as Error).message}`);
    }

    const result = this.validate(tx, rawCbor);
    if (!result.ok) return result;
    return { ok: true, tx };
  }

  /** Run ledger rules against an already-parsed transaction. */
  validate(tx: Transaction, rawCbor: Uint8Array): ValidationResult {
    // U1: at least one input
    if (tx.body.inputs.length === 0) return err('U1: transaction has no inputs');

    // U2: all inputs exist in UTxO set
    const inputUTxOs: UTxO[] = [];
    for (const inp of tx.body.inputs) {
      const utxo = this.state.getUTxO(inp);
      if (!utxo) {
        return err(`U2: input ${inp.txHash}#${inp.index} not found in UTxO set`);
      }
      inputUTxOs.push(utxo);
    }

    // U3: no duplicate inputs
    {
      const seen = new Set<string>();
      for (const inp of tx.body.inputs) {
        const key = `${inp.txHash}#${inp.index}`;
        if (seen.has(key)) return err(`U3: duplicate input ${key}`);
        seen.add(key);
      }
    }

    const slot = this.state.currentSlot();

    // U4: TTL
    if (tx.body.ttl !== undefined && slot > tx.body.ttl) {
      return err(`U4: transaction expired — TTL ${tx.body.ttl}, current slot ${slot}`);
    }

    // U5: validity start
    if (tx.body.validityStart !== undefined && slot < tx.body.validityStart) {
      return err(`U5: tx not yet valid — validityStart ${tx.body.validityStart}, current slot ${slot}`);
    }

    // U6: size limit
    if (rawCbor.length > this.params.maxTxSize) {
      return err(`U6: tx size ${rawCbor.length} B > maxTxSize ${this.params.maxTxSize} B`);
    }

    // N1: network id check
    if (tx.body.networkId !== undefined && tx.body.networkId !== NETWORK_ID) {
      return err(`N1: tx network_id ${tx.body.networkId} ≠ protocol network ${NETWORK_ID}`);
    }

    // N2: output addresses must live on this network
    for (let i = 0; i < tx.body.outputs.length; i++) {
      const aNet = networkIdOfAddress(tx.body.outputs[i].addressHex);
      if (aNet !== null && aNet !== NETWORK_ID) {
        return err(
          `N2: output ${i} address is on network ${aNet}, expected ${NETWORK_ID}`,
        );
      }
    }

    // U7: non-negative outputs and non-negative fee
    if (tx.body.fee < 0n) return err(`U7: fee must be ≥ 0, got ${tx.body.fee}`);
    for (let i = 0; i < tx.body.outputs.length; i++) {
      if (tx.body.outputs[i].value.lovelace < 0n) {
        return err(`U7: output ${i} has negative lovelace`);
      }
    }

    // U8: min-ADA per output (Conway coinsPerUTxOByte rule)
    for (let i = 0; i < tx.body.outputs.length; i++) {
      const out    = tx.body.outputs[i];
      const minAda = this.minAda(out);
      if (out.value.lovelace < minAda) {
        return err(
          `U8: output ${i} lovelace ${out.value.lovelace} < minADA ${minAda}` +
          ` (coinsPerUTxOByte=${this.params.coinsPerUTxOByte})`,
        );
      }
    }

    // U9: fee ≥ minFee
    const minFee = this.minFee(rawCbor.length);
    if (tx.body.fee < minFee) {
      return err(`U9: fee ${tx.body.fee} < minFee ${minFee} (txSize=${rawCbor.length} B)`);
    }

    // U10: value preservation
    {
      const consumed = sumLovelace(inputUTxOs.map(u => u.output.value));
      const produced = sumLovelace(tx.body.outputs.map(o => o.value)) + tx.body.fee;

      if (consumed !== produced) {
        return err(
          `U10: value not preserved — consumed ${consumed} ≠ produced+fee ${produced}` +
          ` (diff ${consumed - produced})`,
        );
      }

      // Multi-asset preservation (no minting)
      if (!tx.body.mint) {
        const ca = sumMultiAsset(inputUTxOs.map(u => u.output.value));
        const pa = sumMultiAsset(tx.body.outputs.map(o => o.value));
        if (!multiAssetEq(ca, pa)) {
          return err('U10: multi-asset value not preserved (no mint field)');
        }
      }
    }

    // W1 + W2: vkey witnesses
    {
      const witnessResult = this.validateWitnesses(tx, inputUTxOs);
      if (!witnessResult.ok) return witnessResult;
    }

    return { ok: true };
  }

  // ── Protocol computations ─────────────────────────────────────────────────

  /** Shelley/Conway minimum fee formula: minFeeA × |tx| + minFeeB */
  minFee(txSizeBytes: number): bigint {
    return BigInt(this.params.minFeeA) * BigInt(txSizeBytes) + BigInt(this.params.minFeeB);
  }

  /**
   * Conway min-ADA formula:
   *   minADA = coinsPerUTxOByte × (utxoOverhead + |serialise(output)|)
   *
   * utxoOverhead = 160 bytes (fixed UTxO entry metadata).
   * We approximate the serialised output size rather than re-encoding CBOR.
   */
  minAda(output: TxOutput): bigint {
    const UTXO_OVERHEAD = 160;
    const approxSize    = estimateOutputSize(output);
    return BigInt(this.params.coinsPerUTxOByte) * BigInt(UTXO_OVERHEAD + approxSize);
  }

  // ── Witness validation ────────────────────────────────────────────────────

  private validateWitnesses(tx: Transaction, inputUTxOs: UTxO[]): ValidationResult {
    // Build a map: paymentKeyHash (hex) → witness
    const witnessIndex = new Map<string, VKeyWitness>();

    for (const w of tx.witnesses.vkeyWitnesses) {
      const vkeyBytes = fromHex(w.vkey);
      if (vkeyBytes.length !== 32) {
        return err(`W1: vkey must be 32 bytes, got ${vkeyBytes.length}`);
      }
      const sigBytes = fromHex(w.signature);
      if (sigBytes.length !== 64) {
        return err(`W1: signature must be 64 bytes, got ${sigBytes.length}`);
      }

      // W1: verify the signature over the tx body hash
      // tx.hash == blake2b-256(CBOR(txBody)) — see ledgerTxToInternal()
      const txBodyHash = fromHex(tx.hash);
      const valid = verifyEd25519(vkeyBytes, txBodyHash, sigBytes);
      if (!valid) {
        const kh = toHex(blake2b224(vkeyBytes));
        return err(`W1: invalid Ed25519 signature for key ${kh}`);
      }

      const kh = toHex(blake2b224(vkeyBytes));
      witnessIndex.set(kh, w);
    }

    // W2: every key-locked input must have a corresponding witness.
    // For type-7/1/2/3 (script) inputs we DO NOT skip silently — until Plutus
    // is wired up the devnet refuses to spend script-locked UTxOs.
    for (const utxo of inputUTxOs) {
      const addrType = addressTypeNibble(utxo.output.addressHex);
      const kh       = paymentKeyHashOfAddress(utxo.output.addressHex);

      if (kh === null) {
        return err(
          `W2: input ${utxo.input.txHash}#${utxo.input.index} is script-locked ` +
          `(addr type ${addrType}); script execution is not supported on the devnet yet`,
        );
      }
      if (!witnessIndex.has(kh)) {
        return err(
          `W2: missing witness for paymentKeyHash ${kh}` +
          ` (input ${utxo.input.txHash}#${utxo.input.index})`,
        );
      }
    }

    // W3: every body.required_signers hash must have a corresponding witness
    for (const kh of tx.body.requiredSigners ?? []) {
      if (!witnessIndex.has(kh)) {
        return err(`W3: missing witness for declared required signer ${kh}`);
      }
    }

    return { ok: true };
  }
}

// ── cardano-ledger-ts → internal conversion ───────────────────────────────────

function ledgerTxToInternal(ledgerTx: LedgerTx, slot: number): Transaction {
  const body = ledgerTx.body;

  // Transaction hash = blake2b-256(CBOR(txBody)) = body.hash from library
  const txHash = ledgerTx.hash.toString();

  const inputs: TxInput[] = body.inputs.map(u => ({
    txHash: u.utxoRef.id.toString(),
    index:  u.utxoRef.index,
  }));

  const refInputs: TxInput[] = (body.refInputs ?? []).map(u => ({
    txHash: u.utxoRef.id.toString(),
    index:  u.utxoRef.index,
  }));

  const outputs: TxOutput[] = body.outputs.map(o => convertOutput(o));

  const fee = body.fee ?? 0n;

  const mint = body.mint ? convertValue(body.mint).assets : undefined;

  const vkeyWitnesses: VKeyWitness[] = (ledgerTx.witnesses.vkeyWitnesses ?? []).map(w => ({
    vkey:      w.vkey.toString(),
    signature: w.signature.toString(),
  }));

  const requiredSigners = ((body as any).requiredSigners ?? []) as Array<{ toString(): string }>;
  const collInputs: TxInput[] = ((body as any).collateralInputs ?? []).map((u: any) => ({
    txHash: u.utxoRef.id.toString(),
    index:  u.utxoRef.index,
  }));

  return {
    hash:      txHash,
    body: {
      inputs,
      referenceInputs: refInputs,
      outputs,
      fee,
      ttl:           body.ttl !== undefined   ? Number(body.ttl)  : undefined,
      validityStart: body.validityIntervalStart !== undefined
                       ? Number(body.validityIntervalStart) : undefined,
      mint,
      networkId: body.network !== undefined ? (body.network === 'mainnet' ? 1 : 0) : undefined,
      requiredSigners: requiredSigners.length ? requiredSigners.map(h => h.toString()) : undefined,
      auxDataHash: (body as any).auxDataHash?.toString(),
      collateralInputs: collInputs.length ? collInputs : undefined,
    },
    witnesses: { vkeyWitnesses },
    isValid:   ledgerTx.isScriptValid,
    slot,
  };
}

function convertOutput(o: { address: Address; value: LedgerValue; datum?: unknown }): TxOutput {
  const addrBytes = Uint8Array.from(o.address.toBytes());
  const addressHex = toHex(addrBytes);

  // bech32 using cardano-ledger-ts so the encoding is canonical
  const addressBech32 = o.address.toString();

  const value = convertValue(o.value);

  return { addressHex, addressBech32, value };
}

function convertValue(v: LedgerValue): Value {
  // toUnits() returns a flat list of { unit, quantity } where unit is
  // 'lovelace' for ADA and `${policyId}${assetName}` for native tokens.
  const units = v.toUnits();
  const assets: MultiAsset = {};
  let lovelace = 0n;
  let hasAssets = false;

  for (const { unit, quantity } of units) {
    const qty = BigInt(quantity);
    if (unit === 'lovelace' || unit === '') {
      lovelace += qty;
      continue;
    }
    // policyId is the first 56 hex chars (28 bytes); the rest is asset name
    const pid  = unit.slice(0, 56);
    const name = unit.slice(56);
    if (!assets[pid]) assets[pid] = {};
    assets[pid][name] = (assets[pid][name] ?? 0n) + qty;
    hasAssets = true;
  }

  return { lovelace, assets: hasAssets ? assets : undefined };
}

// ── Value arithmetic ──────────────────────────────────────────────────────────

function sumLovelace(values: Value[]): bigint {
  return values.reduce((acc, v) => acc + v.lovelace, 0n);
}

function sumMultiAsset(values: Value[]): MultiAsset {
  const result: MultiAsset = {};
  for (const v of values) {
    if (!v.assets) continue;
    for (const [pid, assets] of Object.entries(v.assets)) {
      if (!result[pid]) result[pid] = {};
      for (const [name, qty] of Object.entries(assets)) {
        result[pid][name] = (result[pid][name] ?? 0n) + qty;
      }
    }
  }
  return result;
}

function multiAssetEq(a: MultiAsset, b: MultiAsset): boolean {
  const pidsA = Object.keys(a).sort();
  const pidsB = Object.keys(b).sort();
  if (pidsA.join(',') !== pidsB.join(',')) return false;
  for (const pid of pidsA) {
    const namesA = Object.keys(a[pid]).sort();
    const namesB = Object.keys(b[pid] ?? {}).sort();
    if (namesA.join(',') !== namesB.join(',')) return false;
    for (const name of namesA) {
      if (a[pid][name] !== b[pid][name]) return false;
    }
  }
  return true;
}

// ── Address utilities ─────────────────────────────────────────────────────────

/**
 * Extract the payment key hash from a raw address hex string.
 * Returns null for script-locked or unrecognised address types.
 *
 * Cardano address header byte layout (bits 7-4 = type, bits 3-0 = network):
 *   type 6 (0110) = enterprise key
 *   type 0 (0000) = base key + key
 *   type 4 (0100) = pointer key
 *   type 8 (1000) = Byron
 *   type 7/1/2/3 = script-locked
 */
function paymentKeyHashOfAddress(addressHex: string): string | null {
  try {
    const bytes     = Buffer.from(addressHex, 'hex');
    const header    = bytes[0];
    const typeNibble = (header >> 4) & 0xf;
    // Key-payment types: 0 (base key+key), 4 (pointer key), 6 (enterprise key)
    if (typeNibble === 0 || typeNibble === 4 || typeNibble === 6) {
      return bytes.slice(1, 29).toString('hex');
    }
    return null; // script or Byron
  } catch {
    return null;
  }
}

/** Header type nibble (high 4 bits of byte 0). null if undecodable. */
function addressTypeNibble(addressHex: string): number | null {
  try {
    const b = Buffer.from(addressHex, 'hex');
    return (b[0] >> 4) & 0xf;
  } catch { return null; }
}

/**
 * Network nibble (low 4 bits of byte 0) for Shelley-era addresses.
 * Byron addresses (type 8) carry no network nibble — return null.
 */
function networkIdOfAddress(addressHex: string): number | null {
  try {
    const b = Buffer.from(addressHex, 'hex');
    const typeNibble = (b[0] >> 4) & 0xf;
    if (typeNibble === 8) return null; // Byron
    return b[0] & 0xf;
  } catch { return null; }
}

// ── Output size estimation ────────────────────────────────────────────────────

/**
 * Approximate the CBOR-serialised size of a transaction output for
 * the Conway min-ADA calculation.
 *
 * We deliberately overestimate slightly (adds safety margin) without
 * needing to actually CBOR-encode the output.
 */
function estimateOutputSize(o: TxOutput): number {
  const addrBytes    = o.addressHex.length / 2;          // raw address bytes
  const lovelaceSize = 9;                                 // max CBOR uint64
  let assetSize      = 0;

  if (o.value.assets) {
    for (const [, assets] of Object.entries(o.value.assets)) {
      assetSize += 34; // policy id (28 B) + map overhead
      for (const [name,] of Object.entries(assets)) {
        assetSize += name.length / 2 + 9; // asset name + quantity
      }
    }
  }

  const datumSize = o.datumHash ? 34 : o.inlineDatum ? o.inlineDatum.length / 2 + 2 : 0;

  return addrBytes + lovelaceSize + assetSize + datumSize + 10; // 10 = CBOR framing
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function err(msg: string): ValidationError {
  return { ok: false, error: msg };
}

/**
 * Normalise a top-level transaction CBOR so the harmonic library can parse it.
 *
 * Conway txs are encoded as a 4-element array: `[body, witnesses, isValid, aux]`.
 * The aux-data field at position 3 may be `null` or one of:
 *   - Shelley map (CborMap)
 *   - Shelley-multiasset array `[map, [native_scripts]]`
 *   - Conway tagged Tag(259, { 0?:metadata, 1?:scripts, 2?:pV1, 3?:pV2, 4?:pV3 })
 *
 * `@harmoniclabs/cardano-ledger-ts` mishandles the Conway shape when some of
 * the optional script fields are absent (which is the canonical encoding for
 * a tx with metadata only). When that happens we replace the aux field with
 * CBOR null and re-encode. The body bytes are unchanged so the body hash, the
 * tx ID and every signature remain valid.
 */
function normaliseTxCbor(raw: Uint8Array): Uint8Array {
  let outer: unknown;
  try {
    outer = cbor.decode(Buffer.from(raw));
  } catch {
    return raw; // can't even decode — let harmonic emit the real error
  }
  if (!Array.isArray(outer) || outer.length < 3) return raw;

  const auxField = outer[3];
  if (auxField === null || auxField === undefined) return raw;

  // Quick "can harmonic parse this?" probe: try LedgerTx.fromCbor on the
  // original bytes. If it works, ship as-is. We avoid running the parse
  // twice in the common path by relying on caller's catch — but here we
  // do the cheaper check: only normalise when aux is a Tag-wrapped value
  // (Conway shape), which is the only branch that's known to misbehave.
  const isCborTag =
    typeof auxField === 'object' &&
    auxField !== null &&
    'tag' in (auxField as Record<string, unknown>) &&
    'value' in (auxField as Record<string, unknown>);
  if (!isCborTag) return raw;

  // Replace position 3 with CBOR null and re-encode.
  const next = [outer[0], outer[1], outer[2], null];
  try {
    return new Uint8Array(cbor.encode(next));
  } catch {
    return raw;
  }
}
