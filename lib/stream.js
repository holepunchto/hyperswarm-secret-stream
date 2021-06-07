const { Duplex } = require('streamx')

// Universal wrapper so you can send/recv noise messages
// whether or not you have the rawStream bridge or the noise stream

module.exports = class NoiseStream extends Duplex {
  constructor (noiseStream) {
    super()
    this.noiseStream = noiseStream || this
  }

  send (data) {
    this.noiseStream.write(data)
  }

  recv (fn) {
    // TODO: hook into streamx to avoid data listener here for MAX PERF
    this.noiseStream.on('data', fn)
  }
}
