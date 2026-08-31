import { Duplex, type DuplexEvents } from 'streamx'
import Bridge from './lib/bridge'
import {
  type KeyPair,
  type HandshakePattern,
  type HandshakeReturn as Handshake
} from './lib/handshake'

interface NoiseSecretStreamJSON {
  isInitiator: boolean
  publicKey: string | null
  remotePublicKey: string | null
  connected: boolean
  destroying: boolean
  destroyed: boolean
  rawStream: Duplex | null
}

interface NoiseSecretStreamEvents extends DuplexEvents {
  /**
   * Emitted when the handshake is fully done. It is safe to write to the stream immediately though, as data is buffered internally before the handshake has been completed.
   */
  connect: []
  data: [data: Uint8Array]
  handshake: []
  /**
   * Emitted when an unordered message is received.
   */
  message: [message: Uint8Array]
}

/**
 * `options`
 */
interface NoiseSecretStreamOptions {
  /** Which noise pattern to use. */
  pattern?: HandshakePattern
  /** Set if your handshake requires it. */
  remotePublicKey?: Uint8Array
  keyPair?: KeyPair | Promise<KeyPair>
  /** If you want to use a handshake performed elsewhere, pass it here. */
  handshake?: Handshake
  /** (advanced) set false to disable the send API. */
  enableSend?: boolean
  /** Set false to call `start()` manually instead of automatically starting on construction. */
  autoStart?: boolean
  data?: Uint8Array
  ended?: boolean
  keepAlive?: number
  publicKey?: Uint8Array
}

type NoiseSecretStreamStartOptions = Pick<
  NoiseSecretStreamOptions,
  'data' | 'ended' | 'handshake' | 'keyPair'
>

interface NoiseSecretStream<
  S extends Duplex = Bridge,
  M extends NoiseSecretStreamEvents = NoiseSecretStreamEvents
> extends Duplex<M> {
  readonly noiseStream: this

  readonly isInitiator: boolean

  readonly rawStream: S | null

  /**
   * Get the remote's public key. Populated after `open` is emitted.
   */
  readonly remotePublicKey: Uint8Array | null

  /**
   * Get the unique hash of this handshake. Populated after `open` is emitted.
   */
  readonly handshakeHash: Uint8Array | null

  readonly connected: boolean

  /**
   * Get the interval (in milliseconds) at which keep-alive messages are sent (0 means none are sent).
   */
  readonly keepAlive: number

  readonly timeout: number

  readonly enableSend: boolean

  readonly opened: Promise<boolean>

  /**
   * The number of bytes (measured after encryption) written.
   */
  readonly rawBytesRead: number
  /**
   * The number of bytes (measured before decryption) received.
   */
  readonly rawBytesWritten: number

  /**
   * Get the local public key.
   */
  publicKey: unknown

  userData: unknown
  relay: unknown
  puncher: unknown

  /**
   * Set the stream timeout. If no data is received within a `ms` window, the stream is auto destroyed.
   * @param ms - Timeout in milliseconds.
   */
  setTimeout(ms?: number): void
  /**
   * Send a heartbeat (empty message) every time the socket is idle for `ms` milliseconds.
   * @param ms - Interval in milliseconds.
   */
  setKeepAlive(ms?: number): void
  /**
   * A convenience method that sends an empty message.
   */
  sendKeepAlive(): void

  /**
   * Start a SecretStream from a rawStream asynchronously (used with `autoStart: false`).
   * @param rawStream - An underlying transport stream you want to run the noise stream over.
   * @param opts - `options`
   */
  start(rawStream?: S | null, opts?: NoiseSecretStreamStartOptions): void

  flush(): Promise<boolean>

  /**
   * Sends an encrypted unordered message. Silently fails if called before the handshake is complete or if the underlying `rawStream` is not a UDX-stream.
   * @param buffer - Message to send.
   */
  send(buffer: Uint8Array): Promise<boolean> | undefined

  /**
   * Same as `send(buffer)` but does not return a promise.
   * @param buffer - Message to send.
   */
  trySend(buffer: Uint8Array): void

  alloc(len: number): Uint8Array

  toJSON(): NoiseSecretStreamJSON
}

declare class NoiseSecretStream<
  S extends Duplex = Bridge,
  M extends NoiseSecretStreamEvents = NoiseSecretStreamEvents
> extends Duplex<M> {
  /**
   * Make a new stream. `isInitiator` is a boolean indicating whether you are the client or the server.
   * @param isInitiator - Whether you are the client (`true`) or the server (`false`).
   * @param rawStream - An underlying transport stream you want to run the noise stream over.
   * @param opts - `options`
   */
  constructor(isInitiator: boolean, rawStream: S, opts?: NoiseSecretStreamOptions)
  constructor(isInitiator: boolean, rawStream?: null, opts?: NoiseSecretStreamOptions)

  /**
   * Generate an ed25519 key pair.
   * @param seed - Optional seed.
   */
  static keyPair(seed?: Uint8Array): KeyPair

  static id(handshakeHash: Uint8Array, isInitiator: boolean, id?: Uint8Array): Uint8Array
}

declare namespace NoiseSecretStream {
  export {
    NoiseSecretStream,
    type NoiseSecretStreamEvents,
    type NoiseSecretStreamOptions,
    type NoiseSecretStreamStartOptions,
    type NoiseSecretStreamJSON
  }
}

export = NoiseSecretStream
