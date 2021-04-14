const tape = require('tape')
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
