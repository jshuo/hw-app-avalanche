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
    let hashedTx: Buffer;
    var HDKey = require('hdkey')
    var secp256k1 = require('secp256k1')
    let resultMap: Map<string, Buffer> = new Map();
    for (let i = 0; i < paths.length; i++) {
      let suffix = paths[i]
      let bip32path = `${prefixPath}/${suffix}`
      hashedTx = Buffer.from(createHash('sha256').update(txn).digest())
      var seed = '60999fdc8afa350aa27d6f42dc5b1aeb0bf7690191254b3b5abcee1653a6ef9801a3497900d57bc6cde16c012b5e6fbd53cd042a0b3c0a8716f6c272aaf8f0b2'
      var hdkey = HDKey.fromMasterSeed(Buffer.from(seed, 'hex'))
      var childkey = hdkey.derive(bip32path)
      const ret = secp256k1.ecdsaSign(hashedTx, childkey._privateKey)
      const signature = Buffer.from(ret.signature)
      const recid = ret.recid
      var v = new Uint8Array(1)
      v[0] = recid
      const signatures = new Uint8Array([...signature, ...v])
      resultMap.set(suffix.toString(true), signatures);
    }
    return {
      hash: hashedTx,
      signatures: resultMap
    }
  }
}