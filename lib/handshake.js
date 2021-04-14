const sodium = require('sodium-universal')
const noise = require('noise-protocol')
const { generateKeypair, generateSeedKeypair, SKLEN, PKLEN } = require('noise-protocol/dh')
const { getHandshakeHash } = require('noise-protocol/symmetric-state')

const EMPTY = Buffer.alloc(0)

module.exports = class Handshake {
  constructor (isInitiator, keyPair, pattern) {
    this.isInitiator = isInitiator
    this.keyPair = keyPair
    this.noise = noise.initialize(pattern, this.isInitiator, EMPTY, this.keyPair, null, null)
    this.destroyed = false
  }

  static keyPair (seed) {
    const publicKey = Buffer.alloc(PKLEN)
    const secretKey = Buffer.alloc(SKLEN)
    if (seed) generateSeedKeypair(publicKey, secretKey, seed)
    else generateKeypair(publicKey, secretKey)
    return { publicKey, secretKey }
  }

  recv (data) {
    try {
      const split = noise.readMessage(this.noise, data, EMPTY)
      if (split) return this._return(null, split)
      return this.send()
    } catch (err) {
      this.destroy()
      return null
    }
  }

  // note that the data returned here is framed so we don't have to do an extra copy
  // when sending it...
  send () {
    try {
      const slab = Buffer.allocUnsafe(128)
      const split = noise.writeMessage(this.noise, EMPTY, slab.subarray(3))
      const data = slab.subarray(0, 3 + noise.writeMessage.bytes)

      writeUint24le(noise.writeMessage.bytes, data)
      return this._return(data, split)
    } catch (err) {
      this.destroy()
      return null
    }
  }

  destroy () {
    if (this.destroyed) return
    this.destroyed = true
    noise.destroy(this.noise)
  }

  _return (data, split) {
    // the key copy is suboptimal but to reduce secure memory overhead on linux with default settings
    // better fix is to batch mallocs in noise-protocol
    const tx = split ? Buffer.from(split.tx) : null
    const rx = split ? Buffer.from(split.rx) : null
    const handshakeHash = split ? Buffer.allocUnsafe(64) : null
    const remotePublicKey = split ? Buffer.from(this.noise.rs) : null

    if (split) {
      getHandshakeHash(this.noise.symmetricState, handshakeHash)
      sodium.sodium_free(split.tx)
      sodium.sodium_free(split.rx)
      this.destroy()
    }

    return {
      data,
      remotePublicKey,
      handshakeHash,
      tx,
      rx
    }
  }
}

function writeUint24le (n, buf) {
  buf[0] = (n & 255)
  buf[1] = (n >>> 8) & 255
  buf[2] = (n >>> 16) & 255
}
