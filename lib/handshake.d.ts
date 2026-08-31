interface KeyPair {
  publicKey: Uint8Array
  secretKey: Uint8Array
}

type HandshakePattern = 'NN' | 'NNpsk0' | 'XX' | 'XXpsk0' | 'IK' | 'XK'

interface HandshakeReturn {
  data: Uint8Array
  remotePublicKey: Uint8Array
  hash: Uint8Array
  tx: Uint8Array
  rx: Uint8Array
}

interface Handshake {
  readonly isInitiator: boolean
  readonly keyPair: KeyPair
  readonly noise: unknown
  readonly destroyed: boolean

  recv(data: Uint8Array): HandshakeReturn | null
  send(): HandshakeReturn | null

  destroy(): void
}

declare class Handshake {
  constructor(
    isInitiator: boolean,
    keyPair: KeyPair,
    remotePublicKey: Uint8Array | null,
    pattern: HandshakePattern
  )

  static keyPair(seed?: Uint8Array): KeyPair
}

declare namespace Handshake {
  export { Handshake, type HandshakePattern, type HandshakeReturn, type KeyPair }
}

export = Handshake
