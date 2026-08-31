import { Duplex } from 'streamx'

interface ReversePassThrough extends Duplex {}

declare class Bridge extends Duplex {
  readonly noiseStream: Duplex
  readonly reverse: ReversePassThrough

  readonly publicKey: Uint8Array | null
  readonly remotePublicKey: Uint8Array | null
  readonly handshakeHash: Uint8Array | null

  flush(): Promise<boolean>
}

declare namespace Bridge {
  export { Bridge, type ReversePassThrough }
}

export = Bridge
