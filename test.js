const tape = require('tape')
const NoiseSecretStream = require('./')

tape('connects', function (t) {
  t.plan(2)

  const a = new NoiseSecretStream(true)
  const b = new NoiseSecretStream(false)

  a.pipe(b).pipe(a)

  a.on('connect', function () {
    t.same(a.remotePublicKey, b.publicKey)
  })

  b.on('connect', function () {
    t.same(b.remotePublicKey, a.publicKey)
  })
})

tape('send after connect', function (t) {
  t.plan(2)

  const a = new NoiseSecretStream(true)
  const b = new NoiseSecretStream(false)

  a.pipe(b).pipe(a)

  a.on('connect', function () {
    a.send(Buffer.from('hello'))
  })

  b.on('connect', function () {
    b.send(Buffer.from('world'))
  })

  a.on('message', function (message) {
    t.same(message, Buffer.from('world'))
  })

  b.on('message', function (message) {
    t.same(message, Buffer.from('hello'))
  })
})

tape('send before connect', function (t) {
  t.plan(2)

  const a = new NoiseSecretStream(true)
  const b = new NoiseSecretStream(false)

  a.pipe(b).pipe(a)
  a.send(Buffer.from('hello'))
  b.send(Buffer.from('world'))

  a.on('message', function (message) {
    t.same(message, Buffer.from('world'))
  })

  b.on('message', function (message) {
    t.same(message, Buffer.from('hello'))
  })
})

tape('send bulk later', function (t) {
  t.plan(10)

  const a = new NoiseSecretStream(true)
  const b = new NoiseSecretStream(false)

  a.pipe(b).pipe(a)

  const expected = []

  for (let i = 0; i < 10; i++) {
    expected.push(Buffer.from('hello #' + i))
  }

  setImmediate(function () {
    for (let i = 0; i < expected.length; i++) {
      a.send(expected[i])
    }
  })

  let i = 0
  b.on('message', function (message) {
    t.same(message, expected[i++])
  })
})

tape('send bulk inplace later', function (t) {
  t.plan(10)

  const a = new NoiseSecretStream(true)
  const b = new NoiseSecretStream(false)

  a.pipe(b).pipe(a)

  setImmediate(function () {
    for (let i = 0; i < 10; i++) {
      const s = 'hello #' + i
      const b = a.alloc(s.length)
      b.write(s)
      a.send(b)
    }
  })

  let i = 0
  b.on('message', function (message) {
    t.same(message, Buffer.from('hello #' + i++))
  })
})
