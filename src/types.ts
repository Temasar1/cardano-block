/**
 * Internal devnet types.
 *
 * We keep our own types (rather than re-exporting cardano-ledger-ts directly)
 * so the API server, block producer and CLI can stay decoupled from the
 * parsing library.  The ledger state stores UTxOs in this canonical form;
 * the validator converts cardano-ledger-ts objects to these on entry.
 */

export type TxHash   = string; // 64-char hex  (32 bytes blake2b-256)
export type Slot     = number;
export type Lovelace = bigint;
export type PolicyId = string; // 56-char hex  (28 bytes)
export type AssetName = string; // hex-encoded asset name bytes

// policyId → assetName → quantity
export type MultiAsset = Record<PolicyId, Record<AssetName, Lovelace>>;

export interface Value {
  lovelace: Lovelace;
  assets?: MultiAsset;
}

export interface TxInput {
  txHash: TxHash;
  index:  number;
}

export interface TxOutput {
  /** Raw address bytes as lowercase hex (29–57 bytes) */
  addressHex:    string;
  /** Bech32 rendering for display / API responses */
  addressBech32: string;
  value:         Value;
  datumHash?:    string; // 64-char hex
  inlineDatum?:  string; // CBOR hex of inline datum
  scriptRef?:    string; // CBOR hex of reference script
}

export interface UTxO {
  input:  TxInput;
  output: TxOutput;
}

export interface TransactionBody {
  inputs:          TxInput[];
  referenceInputs: TxInput[];
  outputs:         TxOutput[];
  fee:             Lovelace;
  ttl?:            Slot;
  validityStart?:  Slot;
  mint?:           MultiAsset;
  networkId?:      number;
  /** blake2b-224 payment-key-hashes the body declares must sign the tx. */
  requiredSigners?: string[];
  /** blake2b-256 of the auxiliary data (metadata) — needed for U6/W4. */
  auxDataHash?:    string;
  /** Collateral inputs (only relevant for script txs). */
  collateralInputs?: TxInput[];
}

export interface VKeyWitness {
  /** 32-byte Ed25519 public key, hex */
  vkey:      string;
  /** 64-byte signature, hex */
  signature: string;
}

export interface Transaction {
  hash:      TxHash;
  body:      TransactionBody;
  witnesses: { vkeyWitnesses: VKeyWitness[] };
  isValid:   boolean;
  slot:      Slot;
}

export interface Block {
  hash:        string;
  height:      number;
  slot:        Slot;
  epoch:       number;
  epochSlot:   number;
  time:        number; // unix seconds
  txCount:     number;
  txHashes:    TxHash[];
  previousHash: string;
  /** blake2b-256 over the concatenated tx body hashes (transaction merkle root). */
  bodyHash:    string;
  /** Σ fee for all txs in the block. */
  feesCollected: Lovelace;
}

// ── Genesis ───────────────────────────────────────────────────────────────────

export interface GenesisWallet {
  index:          number;
  /** 32-byte Ed25519 private key seed — hex (test use only) */
  privateKeyHex:  string;
  /**
   * Mesh-compatible CLI envelope: "5820" + privateKeyHex.
   * Pass this to `MeshWallet({ key: { type: 'cli', payment: <here> } })`.
   */
  privateKeyCliHex: string;
  /** 32-byte Ed25519 public key — hex */
  publicKeyHex:   string;
  /** blake2b-224(publicKey) — hex (28 bytes = 56 chars) */
  paymentKeyHash: string;
  addressBech32:  string;
  addressHex:     string;
  initialLovelace: Lovelace;
}
