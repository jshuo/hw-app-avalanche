//@flow

import createHash from 'create-hash';
import { buildPathBuffer} from "@secux/utility";
import { ITransport, StatusCode, TransportStatusError } from "@secux/transport";

function buildTxBuffer(paths: Array<string>, txs: Array<Buffer>, tp: TransactionType, chainId: number) {
  if (paths.length != txs.length) throw Error('Inconsistent length of paths and txs');

  const head = [], data = [];
  for (let i = 0; i < paths.length; i++) {
      const headerBuffer = Buffer.alloc(4);
      headerBuffer.writeUInt16LE(tp, 0);
      headerBuffer.writeUInt16LE(chainId, 2);

      const path = paths[i];
      const { pathNum, pathBuffer } = buildPathBuffer(path);
      // generic prepare can use 3 or 5 path level key to sign
      if (pathNum !== 5 && pathNum !== 3) throw Error('Invalid Path for Signing Transaction');

      head.push(Buffer.concat([Buffer.from([pathNum * 4 + 4]), headerBuffer, pathBuffer]));


      // fixed 2 byte length
      const preparedTxLenBuf = Buffer.alloc(2);
      preparedTxLenBuf.writeUInt16BE(txs[i].length, 0);
      data.push(Buffer.concat([preparedTxLenBuf, txs[i]]));
  }

  return Buffer.concat([Buffer.from([paths.length]), ...head, ...data]);
}


export default class Avalanche {

  constructor(
    transport
  ) {
    this.transport = transport
  }


  async signHash(
    derivationPathPrefix: BIPPath,
    derivationPathSuffixes: Array<BIPPath>,
    hash: Buffer,
  ): Promise<Map<string, Buffer>> {
    if (hash.length != 32) {
      throw "Hash buffer must be 32 bytes";
    }

    const firstMessage: Buffer = Buffer.concat([
      this.uInt8Buffer(derivationPathSuffixes.length),
      hash,
      this.encodeBip32Path(derivationPathPrefix)
    ]);
    const responseHash = await this.transport.send(this.CLA, this.INS_SIGN_HASH, 0x00, 0x00, firstMessage);
    if (!responseHash.slice(0, 32).equals(hash)) {
      throw "Ledger reported a hash that does not match the input hash!";
    }

    return this._collectSignaturesFromSuffixes(derivationPathSuffixes, this.INS_SIGN_HASH, 0x01, 0x81);
  }
  async signTransaction(
    prefixPath,
    paths,
    txn: Buffer,
  ): Promise<{ hash: Buffer, signatures: Map<string, Buffer> }> {
    const SIGNATURE_LENGTH = 65;
    let bip32path = [], txBuffArray = [];
    let resultMap: Map<string, Buffer> = new Map();
    for (let i = 0; i < paths.length; i++) {
      let suffix = paths[i]
      bip32path[i] = `${prefixPath}/${suffix}`
      txBuffArray[i] = Buffer.from(txn)
    }

    const txBuffer = buildTxBuffer(bip32path, txBuffArray);
    const rsp = await this.transport.Send(0x70, 0xa3, 0, 0,
        Buffer.concat([txBuffer]));
        if (rsp.status !== StatusCode.SUCCESS) throw new TransportStatusError(rsp.status);

        if (rsp.dataLength !== SIGNATURE_LENGTH*txBuffArray.length) throw Error('Invalid length Signature');
        let signature = []
        let offset = 0
        while (offset < rsp.dataLength) {
            const sig = rsp.data.slice(offset, offset + SIGNATURE_LENGTH)
            offset = offset + SIGNATURE_LENGTH
            signature.push(sig)
        }
        
    for (let i = 0; i < paths.length; i++) {
      resultMap.set(paths[i].toString(true), signature[i]);
    }
    return {
      hash: '',
      signatures: resultMap
    }
  }
}