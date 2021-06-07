const { Pull, Push, HEADERBYTES, KEYBYTES, ABYTES } = require('sodium-secretstream')
const sodium = require('sodium-universal')
const Stream = require('./lib/stream')
const Bridge = require('./lib/bridge')
const Handshake = require('./lib/handshake')

const IDHEADERBYTES = HEADERBYTES + 32
const NS = Buffer.alloc(32)

sodium.crypto_generichash(NS, Buffer.from('NoiseSecretStream_XChaCha20Poly1305'))

module.exports = class NoiseSecretStream extends Stream {
  constructor (isInitiator, rawStream, opts = {}) {
    super(null)

    this.isInitiator = isInitiator
    this.rawStream = null

    this.publicKey = null
    this.remotePublicKey = null
    this.handshakeHash = null
    this.id = null

    // pointer for upstream to set data here if they want
    this.userData = null

    // unwrapped raw stream
    this._rawStream = null

    // handshake state
    this._idToHandshake = null
    this._handshake = null
    this._handshakeDone = null

    // message parsing state
    this._state = 0
    this._len = 0
    this._tmp = 1
    this._message = null

    this._startDone = null
    this._drainDone = null
    this._outgoingPlain = null
    this._outgoingWrapped = null
    this._utp = null
    this._setup = true
    this._encrypt = null
    this._decrypt = null

    if (opts.autoStart !== false) this.start(rawStream, opts)

    // wiggle it to trigger open immediately (TODO add streamx option for this)
    this.resume()
    this.pause()
  }

  static keyPair (seed) {
    return Handshake.keyPair(seed)
  }

  start (rawStream, opts = {}) {
    if (rawStream) {
      this.rawStream = rawStream
      this._rawStream = rawStream
      if (typeof this.rawStream.setContentSize === 'function') {
        this._utp = rawStream
      }
    } else {
      this.rawStream = new Bridge(this)
      this._rawStream = this.rawStream.reverse
    }

    if (typeof opts.handshake === 'function') {
      this._idToHandshake = opts.handshake
    } else if (opts.handshake) {
      const { tx, rx, handshakeHash, publicKey, remotePublicKey } = opts.handshake
      this._setupSecretStream(tx, rx, handshakeHash, publicKey, remotePublicKey)
    } else {
      this._handshake = new Handshake(this.isInitiator, opts.keyPair || Handshake.keyPair(), 'XX')
      this.publicKey = this._handshake.keyPair.publicKey
    }

    if (this._startDone !== null) {
      const done = this._startDone
      this._startDone = null
      this._open(done)
    }
  }

  _onrawdata (data) {
    let offset = 0

    do {
      switch (this._state) {
        case 0: {
          while (this._tmp !== 0x1000000 && offset < data.length) {
            const v = data[offset++]
            this._len += this._tmp * v
            this._tmp *= 256
          }

          if (this._tmp === 0x1000000) {
            this._tmp = 0
            this._state = 1
            const unprocessed = data.length - offset
            if (unprocessed < this._len && this._utp !== null) this._utp.setContentSize(this._len - unprocessed)
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

          const unprocessed = data.length - offset

          if (this._message === null) {
            this._message = Buffer.allocUnsafe(this._len)
          }

          data.copy(this._message, this._tmp, offset)
          this._tmp += unprocessed

          if (end <= data.length) {
            offset += missing
            this._incoming()
          } else {
            offset += unprocessed
          }

          break
        }
      }
    } while (offset < data.length && !this.destroying)
  }

  _onrawend () {
    this.push(null)
  }

  _onrawdrain () {
    const drain = this._drainDone
    if (drain === null) return
    this._drainDone = null
    drain()
  }

  _read (cb) {
    this.rawStream.resume()
    cb(null)
  }

  _onid (id) {
    const hs = this._idToHandshake(id)

    const done = this._handshakeDone
    this._handshakeDone = null

    if (!hs) {
      done(new Error('No handshake provided'))
    } else {
      this._setupSecretStream(hs.tx, hs.rx, hs.handshakeHash, hs.publicKey, hs.remotePublicKey)
      done(null)
    }
  }

  _incoming () {
    const message = this._message

    this._state = 0
    this._len = 0
    this._tmp = 1
    this._message = null

    if (this._setup === true) {
      if (this._handshake) {
        this._onhandshakert(this._handshake.recv(message))
      } else {
        if (message.byteLength !== IDHEADERBYTES) {
          this.destroy(new Error('Invalid header message received'))
          return
        }

        const expectedId = message.subarray(0, 32)

        if (this._idToHandshake !== null) {
          this._onid(expectedId)
        }

        if (this._decrypt === null) {
          this.destroy(new Error('Invalid handshake'))
          return
        }

        if (!this.id || !this.id.equals(expectedId)) {
          this.destroy(new Error('Remote does not agree on the stream id'))
          return
        }
        this._decrypt.init(message.subarray(32))
        this._setup = false // setup is now done
      }
      return
    }

    if (message.length < ABYTES) {
      this.destroy(new Error('Invalid message received'))
      return
    }

    const plain = message.subarray(1, message.byteLength - ABYTES + 1)

    try {
      this._decrypt.next(message, plain)
    } catch (err) {
      this.destroy(err)
      return
    }

    if (this.push(plain) === false) {
      this.rawStream.pause()
    }
  }

  _onhandshakert (h) {
    if (this._handshakeDone === null) return

    if (h !== null) {
      if (h.data) this._rawStream.write(h.data)
      if (!h.tx) return
    }

    const done = this._handshakeDone
    const publicKey = this._handshake.keyPair.publicKey

    this._handshakeDone = null
    this._handshake = null

    if (h === null) return done(new Error('Noise handshake failed'))

    this._setupSecretStream(h.tx, h.rx, h.handshakeHash, publicKey, h.remotePublicKey)
    done(null)
  }

  _setupSecretStream (tx, rx, handshakeHash, publicKey, remotePublicKey) {
    const buf = Buffer.allocUnsafe(3 + IDHEADERBYTES)
    writeUint24le(IDHEADERBYTES, buf)

    this._encrypt = new Push(tx.subarray(0, KEYBYTES), undefined, buf.subarray(3 + 32))
    this._decrypt = new Pull(rx.subarray(0, KEYBYTES))

    this.publicKey = publicKey
    this.remotePublicKey = remotePublicKey
    this.handshakeHash = handshakeHash
    this.id = buf.subarray(3, 3 + 32)

    sodium.crypto_generichash(this.id, handshakeHash, NS)

    this.emit('handshake')
    // if rawStream is a bridge, also emit it there
    if (this.rawStream !== this._rawStream) this.rawStream.emit('handshake')

    if (this.destroying) return

    this._rawStream.write(buf)
  }

  _open (cb) {
    if (this._rawStream === null) { // no autostart
      this._startDone = cb
      return
    }

    this._rawStream.on('data', this._onrawdata.bind(this))
    this._rawStream.on('end', this._onrawend.bind(this))
    this._rawStream.on('drain', this._onrawdrain.bind(this))

    this.rawStream.on('error', this.destroy.bind(this))
    this.rawStream.on('close', this.destroy.bind(this, null))

    if (this._encrypt !== null) return cb(null)

    this._handshakeDone = cb

    if (this.isInitiator) this._onhandshakert(this._handshake.send())
  }

  _predestroy () {
    if (this._startDone !== null) {
      const done = this._startDone
      this._startDone = null
      done(new Error('Stream destroyed'))
    }

    if (this._handshakeDone !== null) {
      const done = this._handshakeDone
      this._handshakeDone = null
      if (this.rawStream) this.rawStream.destroy()
      done(new Error('Stream destroyed'))
    }

    if (this._drainDone !== null) {
      const done = this._drainDone
      this._drainDone = null
      if (this.rawStream) this.rawStream.destroy()
      done(new Error('Stream destroyed'))
    }
  }

  _write (data, cb) {
    let wrapped = this._outgoingWrapped

    if (data !== this._outgoingPlain) {
      if (typeof data === 'string') data = Buffer.from(data)
      wrapped = Buffer.allocUnsafe(data.byteLength + 3 + ABYTES)
      wrapped.set(data, 4)
    } else {
      this._outgoingWrapped = this._outgoingPlain = null
    }

    writeUint24le(wrapped.byteLength - 3, wrapped)
    this._encrypt.next(wrapped.subarray(4, 4 + data.byteLength), wrapped.subarray(3))

    if (this._rawStream.write(wrapped) === false) {
      this._drainDone = cb
    } else {
      cb(null)
    }
  }

  _final (cb) {
    this._rawStream.end()
    cb(null)
  }

  _destroy (cb) {
    // TODO: pass cb to rawStream
    if (this.rawStream) this.rawStream.destroy()
    cb(null)
  }

  alloc (len) {
    const buf = Buffer.allocUnsafe(len + 3 + ABYTES)
    this._outgoingWrapped = buf
    this._outgoingPlain = buf.subarray(4, buf.byteLength - ABYTES + 1)
    return this._outgoingPlain
  }
}

function writeUint24le (n, buf) {
  buf[0] = (n & 255)
  buf[1] = (n >>> 8) & 255
  buf[2] = (n >>> 16) & 255
}
