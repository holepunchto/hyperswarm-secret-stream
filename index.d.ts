// Type declarations for the holepunchto/hyperswarm-secret-stream public API.
/// <reference types="node" />

/**
 * `options`
 */
export interface NoiseSecretStreamOptions {
  /** Which noise pattern to use. */
  pattern?: any
  /** Set if your handshake requires it. */
  remotePublicKey?: any
  keyPair?: any
  /** If you want to use a handshake performed elsewhere, pass it here. */
  handshake?: any
  /** (advanced) set false to disable the send API. */
  enableSend?: any
  /** Set false to call `start()` manually instead of automatically starting on construction. */
  autoStart?: any
}

export class NoiseSecretStream {
  /**
   * Make a new stream. `isInitiator` is a boolean indicating whether you are the client or the server.
   * @param isInitiator - Whether you are the client (`true`) or the server (`false`).
   * @param rawStream - An underlying transport stream you want to run the noise stream over.
   * @param opts - `options`
   */
  constructor(isInitiator: boolean, rawStream?: any, opts?: NoiseSecretStreamOptions)

  noiseStream: any

  isInitiator: boolean

  rawStream: any

  /**
   * Get the local public key.
   */
  publicKey: any

  /**
   * Get the remote's public key. Populated after `open` is emitted.
   */
  remotePublicKey: any

  /**
   * Get the unique hash of this handshake. Populated after `open` is emitted.
   */
  handshakeHash: any

  connected: boolean

  /**
   * Get the interval (in milliseconds) at which keep-alive messages are sent (0 means none are sent).
   */
  keepAlive: any

  timeout: number

  enableSend: boolean

  userData: any

  opened: Promise<boolean>

  /**
   * The number of bytes (measured after encryption) written.
   */
  rawBytesWritten: number

  /**
   * The number of bytes (measured before decryption) received.
   */
  rawBytesRead: number

  relay: any

  puncher: any

  /**
   * Generate an ed25519 key pair.
   * @param seed - Optional seed.
   */
  static keyPair(seed?: any): any

  static id(handshakeHash: any, isInitiator: boolean, id?: any): any

  /**
   * Set the stream timeout. If no data is received within a `ms` window, the stream is auto destroyed.
   * @param ms - Timeout in milliseconds.
   */
  setTimeout(ms: number): void

  /**
   * Send a heartbeat (empty message) every time the socket is idle for `ms` milliseconds.
   * @param ms - Interval in milliseconds.
   */
  setKeepAlive(ms: number): void

  /**
   * A convenience method that sends an empty message.
   */
  sendKeepAlive(): void

  /**
   * Start a SecretStream from a rawStream asynchronously (used with `autoStart: false`).
   * @param rawStream - An underlying transport stream you want to run the noise stream over.
   * @param opts - `options`
   */
  start(rawStream: any, opts?: NoiseSecretStreamOptions): void

  flush(): Promise<any>

  /**
   * Sends an encrypted unordered message. Silently fails if called before the handshake is complete or if the underlying `rawStream` is not a UDX-stream.
   * @param buffer - Message to send.
   */
  send(buffer: any): Promise<any>

  /**
   * Same as `send(buffer)` but does not return a promise.
   * @param buffer - Message to send.
   */
  trySend(buffer: any): void

  alloc(len: number): any

  toJSON(): any

  /**
   * Emitted when the handshake is fully done. It is safe to write to the stream immediately though, as data is buffered internally before the handshake has been completed.
   */
  on(event: 'connect', listener: () => void): this
  /**
   * Emitted when an unordered message is received.
   */
  on(event: 'message', listener: (message: any) => void): this
  on(event: 'data', listener: () => void): this
  on(event: 'readable', listener: () => void): this
  on(event: 'end', listener: () => void): this
  on(event: 'close', listener: () => void): this
  on(event: 'error', listener: () => void): this
  on(event: 'drain', listener: () => void): this
  on(event: 'finish', listener: () => void): this
}

export default NoiseSecretStream
