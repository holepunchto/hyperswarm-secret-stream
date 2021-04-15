const tape = require('tape')
const net = require('net')
const crypto = require('crypto')
const { Readable } = require('streamx')
const NoiseStream = require('./')

tape('basic', function (t) {
  t.plan(2)

  const a = new NoiseStream(true)
  const b = new NoiseStream(false)

  a.rawStream.pipe(b.rawStream).pipe(a.rawStream)

  a.on('open', function () {
    t.same(a.remotePublicKey, b.publicKey)
  })

  b.on('open', function () {
    t.same(a.publicKey, b.remotePublicKey)
  })
})

tape('data looks encrypted', function (t) {
  t.plan(2)

  const a = new NoiseStream(true)
  const b = new NoiseStream(false)

  a.rawStream.pipe(b.rawStream).pipe(a.rawStream)

  a.write(Buffer.from('plaintext'))

  const buf = []

  a.rawStream.on('data', function (data) {
    buf.push(Buffer.from(data))
  })

  b.on('data', function (data) {
    t.same(data, Buffer.from('plaintext'))
    t.ok(Buffer.concat(buf).indexOf(Buffer.from('plaintext')) === -1)
    t.end()
  })
})

tape('works with external streams', function (t) {
  const server = net.createServer(function (socket) {
    const s = new NoiseStream(false, socket)

    s.on('data', function (data) {
      s.destroy()
      t.same(data, Buffer.from('encrypted!'))
    })
  })

  server.listen(0, function () {
    const socket = net.connect(server.address().port)
    const s = new NoiseStream(true, socket)

    s.write(Buffer.from('encrypted!'))
    s.on('close', function () {
      server.close()
    })
  })

  server.on('close', function () {
    t.end()
  })
})

tape('works with tiny chunks', function (t) {
  const a = new NoiseStream(true)
  const b = new NoiseStream(false)

  const tmp = crypto.randomBytes(40000)

  a.write(Buffer.from('hello world'))
  a.write(tmp)

  a.rawStream.on('data', function (data) {
    for (let i = 0; i < data.byteLength; i++) {
      b.rawStream.write(data.subarray(i, i + 1))
    }
  })

  b.rawStream.on('data', function (data) {
    for (let i = 0; i < data.byteLength; i++) {
      a.rawStream.write(data.subarray(i, i + 1))
    }
  })

  b.once('data', function (data) {
    t.same(data, Buffer.from('hello world'))
    b.once('data', function (data) {
      t.same(data, tmp)
      t.end()
    })
  })
})

tape('async creation', function (t) {
  const server = net.createServer(function (socket) {
    const s = new NoiseStream(false, socket)

    s.on('data', function (data) {
      s.destroy()
      t.same(data, Buffer.from('encrypted!'))
    })
  })

  server.listen(0, function () {
    const s = NoiseStream.async(async () => {
      const socket = net.connect(server.address().port)
      await new Promise((resolve) => socket.once('connect', resolve))
      return [true, socket]
    })

    s.write(Buffer.from('encrypted!'))
    s.on('close', function () {
      server.close()
    })
  })

  server.on('close', function () {
    t.end()
  })
})

tape('send and recv lots of data', function (t) {
  const a = new NoiseStream(true)
  const b = new NoiseStream(false)

  a.rawStream.pipe(b.rawStream).pipe(a.rawStream)

  const buf = crypto.randomBytes(65536)
  let size = 1024 * 1024 * 1024 // 1gb

  const r = new Readable({
    read (cb) {
      this.push(buf)
      size -= buf.byteLength
      if (size <= 0) this.push(null)
      cb(null)
    }
  })

  r.pipe(a)

  const then = Date.now()
  let recv = 0
  let same = true

  b.on('data', function (data) {
    if (same) same = data.equals(buf)
    recv += data.byteLength
  })
  b.on('end', function () {
    t.same(recv, 1024 * 1024 * 1024)
    t.ok(same, 'data was the same')
    t.pass('1gb transfer took ' + (Date.now() - then) + 'ms')
    t.end()
  })
})

tape('send garbage handshake data', function (t) {
  t.plan(2)

  check(Buffer.alloc(65536))
  check(Buffer.from('\x10\x00\x00garbagegarbagegarbage'))

  function check (buf) {
    const a = new NoiseStream(true)

    a.on('error', function () {
      t.pass('handshake errored')
    })

    a.rawStream.write(buf)
  }
})

tape('send garbage secretstream header data', function (t) {
  const a = new NoiseStream(true)
  const b = new NoiseStream(false)

  b.on('error', () => {})

  a.rawStream.pipe(b.rawStream).pipe(a.rawStream)

  a.on('error', function (err) {
    t.pass('header errored')
    t.end()
  })

  a.on('open', function () {
    t.pass('opened')
    a.rawStream.write(Buffer.from([0xff, 0, 0]))
    a.rawStream.write(crypto.randomBytes(0xff))
  })
})

tape('send garbage secretstream payload data', function (t) {
  const a = new NoiseStream(true)
  const b = new NoiseStream(false)

  b.on('error', () => {})
  b.write(Buffer.from('hi'))

  b.on('data', function (data) {
    t.fail('b should not recv messages')
  })

  a.rawStream.pipe(b.rawStream).pipe(a.rawStream)

  a.on('error', function (err) {
    t.pass('payload errored')
    t.end()
  })

  a.once('data', function () {
    t.pass('a got initial message')
    a.rawStream.write(Buffer.from([0xff, 0, 0]))
    a.rawStream.write(crypto.randomBytes(0xff))
  })
})
