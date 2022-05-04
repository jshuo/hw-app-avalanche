//@flow

import createHash from 'create-hash'
import { buildPathBuffer } from '@secux/utility'
import { ITransport, StatusCode, TransportStatusError } from '@secux/transport'

function buildTxBuffer(paths: Array<string>, txs: Buffer, tp: TransactionType, chainId: number) {
  const head = [],
    data = []
  for (let i = 0; i < paths.length; i++) {
    const headerBuffer = Buffer.alloc(4)
    headerBuffer.writeUInt16LE(tp, 0)
    headerBuffer.writeUInt16LE(chainId, 2)

    const path = paths[i]
    const { pathNum, pathBuffer } = buildPathBuffer(path)
    // generic prepare can use 3 or 5 path level key to sign
    if (pathNum !== 5 && pathNum !== 3) throw Error('Invalid Path for Signing Transaction')

    head.push(Buffer.concat([Buffer.from([pathNum * 4 + 4]), headerBuffer, pathBuffer]))
  }
  // fixed 2 byte length
  const preparedTxLenBuf = Buffer.alloc(2)
  preparedTxLenBuf.writeUInt16BE(txs.length, 0)
  data.push(Buffer.concat([preparedTxLenBuf, txs]))
  return Buffer.concat([Buffer.from([paths.length]), ...head, ...data])
}

export default class Avalanche {
  constructor(transport) {
    this.transport = transport
  }
  async signTransaction(prefixPath, paths, changePath, txn: Buffer): Promise<{ hash: Buffer, signatures: Map<string, Buffer> }> {
    const SIGNATURE_LENGTH = 65
    let bip32path = []
    let resultMap: Map<string, Buffer> = new Map()
    for (let i = 0; i < paths.length; i++) {
      let suffix = paths[i]
      bip32path.push(`${prefixPath}/${suffix}`)
    }
    const P1 = changePath !== null ? 0x1 : 0x0
    if (changePath !== null) bip32path.push(changePath)
    const txBuffer = buildTxBuffer(bip32path, Buffer.from(txn))
    const rsp = await this.transport.Send(0x70, 0xa7, P1, 0, Buffer.concat([txBuffer]))
    // if (rsp.status !== StatusCode.SUCCESS) throw new TransportStatusError(rsp.status)
    if (rsp.dataLength !== SIGNATURE_LENGTH * paths.length) throw Error('Invalid length Signature')

    let signature = []
    let offset = 0
    while (offset < rsp.dataLength) {
      const sig = rsp.data.slice(offset, offset + SIGNATURE_LENGTH)
      offset = offset + SIGNATURE_LENGTH
      signature.push(sig)
    }

    for (let i = 0; i < paths.length; i++) {
      resultMap.set(paths[i].toString(true), signature[i])
    }
    return {
      hash: '',
      signatures: resultMap
    }
  }
}
