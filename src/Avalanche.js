//@flow

import createHash from 'create-hash';

export default class Avalanche {

  constructor(
    transport
  ) {
    this.transport = transport
  }

  async signTransaction(
    prefixPath,
    paths,
    txn: Buffer,
  ): Promise<{ hash: Buffer, signatures: Map<string, Buffer> }> {
    let bip32path = [], hashedTx = [], signatures;
    let resultMap: Map<string, Buffer> = new Map();
    for (let i = 0; i < paths.length; i++) {
      let suffix = paths[i]
      bip32path[i] = `${prefixPath}/${suffix}`
      hashedTx[i] = Buffer.from(createHash('sha256').update(txn).digest())
    }
    signatures = await this.transport.SignGroupedHashedTx(bip32path, hashedTx)
    for (let i = 0; i < paths.length; i++) {
      resultMap.set(paths[i].toString(true), signatures[i]);
    }
    return {
      hash: hashedTx,
      signatures: resultMap
    }
  }
}