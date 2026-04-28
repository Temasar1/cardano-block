import { bech32 } from 'bech32';
import type { UTxO, Transaction, Block, TxInput } from '../types.js';

/** Canonical string key for a UTxO input reference. */
function inputKey(i: TxInput): string {
  return `${i.txHash}#${i.index}`;
}

/**
 * In-memory Cardano ledger state.
 *
 * Manages:
 *  - UTxO set  (Map for O(1) lookups)
 *  - Transaction history
 *  - Block chain
 *  - Current slot
 */
export class LedgerState {
  private utxoMap   = new Map<string, UTxO>();
  private txMap     = new Map<string, Transaction>();
  private blockList: Block[] = [];
  private slot      = 0;

  // ── UTxO ─────────────────────────────────────────────────────────────────

  addUTxO(utxo: UTxO): void {
    this.utxoMap.set(inputKey(utxo.input), utxo);
  }

  getUTxO(input: TxInput): UTxO | undefined {
    return this.utxoMap.get(inputKey(input));
  }

  hasUTxO(input: TxInput): boolean {
    return this.utxoMap.has(inputKey(input));
  }

  allUTxOs(): UTxO[] {
    return [...this.utxoMap.values()];
  }

  /**
   * Look up all UTxOs whose address matches.
   * Accepts both hex and bech32; normalises to hex for comparison.
   */
  utxosByAddress(address: string): UTxO[] {
    const needle = normaliseAddress(address);
    return this.allUTxOs().filter(u => normaliseAddress(u.output.addressHex) === needle
      || normaliseAddress(u.output.addressBech32) === needle);
  }

  // ── Transaction application ───────────────────────────────────────────────

  /**
   * Apply a validated transaction to the UTxO set:
   *   1. Remove spent inputs
   *   2. Add new outputs
   *   3. Index the transaction
   */
  applyTx(tx: Transaction): void {
    // Consume inputs
    for (const inp of tx.body.inputs) {
      this.utxoMap.delete(inputKey(inp));
    }

    // Produce outputs
    for (let i = 0; i < tx.body.outputs.length; i++) {
      this.addUTxO({ input: { txHash: tx.hash, index: i }, output: tx.body.outputs[i] });
    }

    this.txMap.set(tx.hash, tx);
  }

  // ── Block chain ───────────────────────────────────────────────────────────

  addBlock(block: Block): void {
    this.blockList.push(block);
    this.slot = block.slot;
  }

  latestBlock(): Block | undefined {
    return this.blockList.at(-1);
  }

  getBlock(id: string | number): Block | undefined {
    if (typeof id === 'number') return this.blockList[id];
    return this.blockList.find(b => b.hash === id);
  }

  allBlocks(): Block[] {
    return this.blockList;
  }

  // ── Transactions ──────────────────────────────────────────────────────────

  getTx(hash: string): Transaction | undefined {
    return this.txMap.get(hash);
  }

  // ── Slot ──────────────────────────────────────────────────────────────────

  currentSlot(): Slot {
    return this.slot;
  }

  setSlot(s: Slot): void {
    this.slot = s;
  }
}

type Slot = number;

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Normalise an address to its lowercase hex form so different
 * representations compare equal.
 */
function normaliseAddress(addr: string): string {
  if (!addr) return '';
  // Already hex
  if (/^[0-9a-fA-F]+$/.test(addr)) return addr.toLowerCase();
  // bech32 → bytes → hex
  try {
    const { words } = bech32.decode(addr, 1000);
    return Buffer.from(bech32.fromWords(words)).toString('hex');
  } catch {
    return addr.toLowerCase();
  }
}
