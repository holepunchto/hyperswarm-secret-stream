const { Duplex } = require('streamx')
const { Pull, Push, HEADERBYTES, KEYBYTES, ABYTES } = require('sodium-secretstream')
const Passthrough = require('./lib/passthrough')
const Handshake = require('./lib/handshake')

module.exports = class NoiseSecretStream extends Duplex {
  constructor (isInitiator, rawStream, opts = {}) {
    super()

    this.isInitiator = isInitiator
    this.rawStream = rawStream || new Passthrough()

    this.publicKey = null
    this.remotePublicKey = null
    this.handshakeHash = null

    this._out = rawStream || this.rawStream.out
    this._inc = rawStream || this.rawStream.inc

    // handshake state
    this._handshake = opts.tx ? null : new Handshake(this.isInitiator, opts.keyPair || Handshake.keyPair(), 'XX')
    this._handshakeDone = null

    // message parsing state
    this._state = 0
    this._len = 0
    this._tmp = 1
    this._message = null

    this._drainDone = null
    this._outgoingPlain = null
    this._outgoingWrapped = null
    this._utp = null
    this._setup = true
    this._encrypt = null
    this._decrypt = null

    if (opts.tx) {
      this._setupSecretStream(opts.tx, opts.rx, opts.handshakeHash, opts.publicKey, opts.remotePublicKey)
    } else {
      this.publicKey = this._handshake.keyPair.publicKey
    }

    // wiggle it to trigger open immediately (TODO add streamx option for this)
    this.resume()
    this.pause()
  }

  static keyPair (seed) {
    return Handshake.keyPair(seed)
  }

  _onrawdata (data) {
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

  _incoming () {
    const message = this._message

    this._state = 0
    this._len = 0
    this._tmp = 1
    this._message = null

    if (this._setup === true) {
      if (this._handshake) {
        this._onhandshakert(this._handshake.recv(message))
      } else if (this._decrypt !== null) {
        this._decrypt.init(message)
        this._setup = false // setup is now done
      }
      return
    }

    const plain = message.subarray(1, message.byteLength - ABYTES + 1)
    this._decrypt.next(message, plain)

    if (this.push(plain) === false) {
      this.rawStream.pause()
    }
  }

  _onhandshakert (h) {
    if (this._handshakeDone === null) return

    if (h !== null) {
      if (h.data) this._out.write(h.data)
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
    const buf = Buffer.allocUnsafe(3 + HEADERBYTES)
    writeUint24le(HEADERBYTES, buf)

    this._encrypt = new Push(tx.subarray(0, KEYBYTES), undefined, buf.subarray(3))
    this._decrypt = new Pull(rx.subarray(0, KEYBYTES))

    this.publicKey = publicKey
    this.remotePublicKey = remotePublicKey
    this.handshakeHash = handshakeHash

    this._out.write(buf)
  }

  _open (cb) {
    if (this._encrypt !== null) return cb(null)

    this._handshakeDone = cb
    if (this.isInitiator) this._onhandshakert(this._handshake.send())

    this._inc.on('data', this._onrawdata.bind(this))
    this._inc.on('end', this._onrawend.bind(this))
    this._out.on('drain', this._onrawdrain.bind(this))

    this.rawStream.on('error', this.destroy.bind(this))
    this.rawStream.on('close', this.destroy.bind(this, null))
  }

  _predestroy () {
    if (this._handshakeDone !== null) {
      const done = this._handshakeDone
      this._handshakeDone = null
      this.rawStream.destroy()
      done(new Error('Stream destroyed'))
    }

    if (this._drainDone !== null) {
      const done = this._drainDone
      this._drainDone = null
      this.rawStream.destroy()
      done(new Error('Stream destroyed'))
    }
  }

  _write (data, cb) {
    let wrapped = this._outgoingWrapped

    if (data !== this._outgoingPlain) {
      wrapped = Buffer.allocUnsafe(data.byteLength + 3 + ABYTES)
      wrapped.set(data, 4)
    } else {
      this._outgoingWrapped = this._outgoingPlain = null
    }

    writeUint24le(wrapped.byteLength - 3, wrapped)
    this._encrypt.next(wrapped.subarray(4, 4 + data.byteLength), wrapped.subarray(3))

    if (this._out.write(wrapped) === false) {
      this._drainDone = cb
    } else {
      cb(null)
    }
  }

  _final (cb) {
    this._out.end()
    cb(null)
  }

  _destroy (cb) {
    // TODO: pass cb to rawStream
    this.rawStream.destroy()
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
