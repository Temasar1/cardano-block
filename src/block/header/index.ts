import crypto from 'crypto';

class Block {
    public index: number;
    public blockHash: string;
    public previousBlockhash: string | null;
    public timestamp: number;
    public data: string;

  constructor(
    index: number,
    blockHash: string,
    previousBlockhash: string | null,
    timestamp: number,
    data: string
  ){
    this.index = index;
    this.blockHash = blockHash;
    this.previousBlockhash = previousBlockhash;
    this.timestamp = timestamp;
    this.data = data;
  }
}

const calculateBlockHash = (index: number, previousBlockhash: string, timestamp: number, data: string) => {
    const blockData = `${index}${previousBlockhash}${timestamp}${data}`;
    return crypto.createHash('sha256').update(blockData).digest('hex');
}

const genesisBlock: Block = new Block(0, "816534932c2b7154836da6afc367695e6337db8a921823784c14378abed4f7d7", null, Date.now(), "my genesis block")

const blockchain: Block[] = [genesisBlock];
const getLatestBlock = () => blockchain[blockchain.length - 1];

const generateNextBlock = (blockData: Block) => {
 const previousBlock : Block = getLatestBlock();
 const nextIndex = previousBlock.index + 1;
 const nextTimestamp = new Date().getTime() / 1000;
 
}