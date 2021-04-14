const { Writable, Readable, Duplex } = require('streamx')

class PassThroughW extends Writable {
  constructor (s) {
    super()
    this._stream = s
  }

  _write (data, cb) {
    if (this._stream.push(data) === false) {
      this._stream._ondrain = cb
    } else {
      cb(null)
    }
  }

  _final (cb) {
    this._stream.push(null)
    cb(null)
  }
}

class PassThroughR extends Readable {
  constructor (s) {
    super()
    this._ondrain = null
  }

  _read (cb) {
    const ondrain = this._ondrain
    this._ondrain = null
    if (ondrain) ondrain()
    cb(null)
  }
}

module.exports = class PassThrough extends Duplex {
  constructor () {
    super()

    this._ondrain = null

    this.out = new PassThroughW(this)
    this.inc = new PassThroughR()
  }

  _read (cb) {
    const ondrain = this._ondrain
    this._ondrain = null
    if (ondrain) ondrain()
    cb(null)
  }

  _write (data, cb) {
    if (this.inc.push(data) === false) {
      this.inc._ondrain = cb
    } else {
      cb(null)
    }
  }

  _final (cb) {
    this.inc.push(null)
    cb(null)
  }
}
