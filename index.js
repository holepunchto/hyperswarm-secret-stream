const { Duplex } = require('streamx')
const { Pull, Push, HEADERBYTES, KEYBYTES, ABYTES } = require('sodium-secretstream')
const sodium = require('sodium-universal')
const noise = require('noise-protocol')
const { generateKeypair, generateSeedKeypair } = require('noise-protocol/dh')

const PROLOUGE = Buffer.from('hypercore')
const EMPTY = Buffer.alloc(0)

module.exports = class NoiseSecretStream extends Duplex {
  constructor (isInitiator, opts = {}) {
    super()

    const keyPair = opts.keyPair || noise.keygen()

    this.isInitiator = isInitiator
    this.publicKey = keyPair.publicKey
    this.remotePublicKey = null

    this._keyPair = keyPair
    this._setup = true
    this._noiseHandshake = null
    this._noiseHandshakeBuffer = Buffer.alloc(100)

    this._tx = null
    this._rx = null
    this._state = 0
    this._len = 0
    this._tmp = 1
    this._message = null
    this._outgoingPending = []
    this._outgoing = null
    this._outgoingPlain = null
    this._utp = null

    this.once('finish', this.push.bind(this, null))
    this.on('pipe', this._onpipe)
  }

  static keyPair (seed, publicKey = Buffer.alloc(noise.PKLEN), secretKey = Buffer.alloc(noise.SKLEN)) {
    if (seed) generateSeedKeypair(seed, publicKey, secretKey)
    else generateKeypair(publicKey, secretKey)
    return { publicKey, secretKey }
  }

  _open (cb) {
    this._noiseHandshake = noise.initialize('XX', this.isInitiator, PROLOUGE, this._keyPair, null, null)
    if (this.isInitiator) this._handshakeRT()
    cb(null)
  }

  _onpipe (dest) {
    if (typeof dest.setContentSize === 'function') this._utp = dest
  }

  _write (data, cb) {
    let offset = 0

    do {
      switch (this._state) {
        case 0: {
          while (this._tmp !== 16777216 && offset < data.length) {
            const v = data[offset++]
            this._len += this._tmp * v
            this._tmp *= 256
          }

          if (this._tmp === 16777216) {
            this._tmp = 0
            this._state = 1
            if (this._utp !== null) this._utp.setContentSize(this._len)
          }

          break
        }

        case 1: {
          const missing = this._len - this._tmp
          const end = missing + offset

          if (this._message === null && end <= data.length) {
            this._message = data.subarray(offset, end)
            offset += missing
            this._incoming()
            break
          }

          if (this._message === null) {
            this._message = Buffer.allocUnsafe(this._len)
          }

          data.copy(this._message, this._tmp, offset)

          if (end <= data.length) {
            offset += missing
            this._incoming()
          } else {
            offset += data.length - offset
          }

          break
        }
      }
    } while (offset < data.length && !this.destroying)

    cb(null)
  }

  _incoming () {
    const message = this._message

    this._state = 0
    this._len = 0
    this._tmp = 1
    this._message = null

    if (this._setup) {
      if (this._noiseHandshake !== null) {
        const split = noise.readMessage(this._noiseHandshake, message, EMPTY)
        if (split) this._onhandshake(split, [])
        else this._handshakeRT()
        return
      }

      // last message, receiving header
      this._rx.init(message)
      this._setup = false
      return
    }

    if (message.length < ABYTES) {
      this.destroy(new Error('Invalid message received'))
      return
    }

    const end = message.length - ABYTES
    const plain = message.subarray(0, end)
    this._rx.next(message, plain)
    this.onmessage(plain)
  }

  onmessage (message) {
    this.emit('message', message)
  }

  alloc (len) {
    const buf = Buffer.allocUnsafe(len + 3 + ABYTES)
    this._outgoing = buf
    this._outgoingPlain = buf.subarray(4, buf.length - ABYTES + 1)
    return this._outgoingPlain
  }

  send (message) {
    const inplace = message === this._outgoingPlain
    const buf = inplace
      ? this._outgoing
      : Buffer.allocUnsafe(message.length + 3 + ABYTES)

    this._outgoing = this._outgoingPlain = null
    writeUint24le(buf.length - 3, buf)

    if (this._outgoingPending !== null) {
      if (inplace === false) buf.set(message, 4)
      this._outgoingPending.push(buf)
      return false
    }

    this._tx.next(message, buf.subarray(3))
    return this.push(buf)
  }

  _handshakeRT () {
    const split = noise.writeMessage(this._noiseHandshake, EMPTY, this._noiseHandshakeBuffer.subarray(3))
    writeUint24le(noise.writeMessage.bytes, this._noiseHandshakeBuffer)
    const message = this._noiseHandshakeBuffer.subarray(0, 3 + noise.writeMessage.bytes)
    if (split) this._onhandshake(split, [message])
    else this.push(message)
  }

  _onhandshake ({ tx, rx }, pendingBuffers) {
    this.remotePublicKey = Buffer.from(this._noiseHandshake.rs)
    noise.destroy(this._noiseHandshake)
    this._noiseHandshake = null

    const buf = Buffer.allocUnsafe(3 + HEADERBYTES)
    writeUint24le(HEADERBYTES, buf)

    // the key copy is suboptimal but to reduce secure memory overhead on linux with default settings
    // better fix is to batch mallocs in noise-protocol

    this._tx = new Push(Buffer.from(tx.subarray(0, KEYBYTES)), undefined, buf.subarray(3))
    this._rx = new Pull(Buffer.from(rx.subarray(0, KEYBYTES)))

    sodium.sodium_free(rx)
    sodium.sodium_free(tx)

    this.emit('connect')
    if (this.destroying) return

    pendingBuffers.push(buf)

    for (const out of this._outgoingPending) {
      this._tx.next(out.subarray(4, out.length - ABYTES + 1), out.subarray(3))
      pendingBuffers.push(out)
    }

    this._outgoingPending = null
    this.push(pendingBuffers.length === 1 ? pendingBuffers[0] : Buffer.concat(pendingBuffers))
  }

  _destroy (cb) {
    if (this._noiseHandshake !== null) {
      noise.destroy(this._noiseHandshake)
      this._noiseHandshake = null
    }

    cb(null)
  }
}

function writeUint24le (n, buf) {
  buf[0] = (n & 255)
  buf[1] = (n >>> 8) & 255
  buf[2] = (n >>> 16) & 255
}
