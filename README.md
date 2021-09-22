# noise-secret-stream

Secret stream backed by Noise and libsodium's secretstream

```
npm install noise-secret-stream
```

## Usage

You can either make a secret stream from an existing transport stream.

``` js
const NoiseSecretStream = require('noise-secret-stream')

const a = new NoiseSecretStream(true, tcpClientStream)
const b = new NoiseSecretStream(false, tcpServerStream)

// pipe the underlying rawstreams together

a.write(Buffer.from('hello encrypted!'))

b.on('data', function (data) {
  console.log(data) // <Buffer hello encrypted!>
})
```

Or by making your own pipeline

``` js
const a = new NoiseSecretStream(true)
const b = new NoiseSecretStream(false)

// pipe the underlying rawstreams together
a.rawStream.pipe(b.rawStream).pipe(a.rawStream)

a.write(Buffer.from('hello encrypted!'))

b.on('data', function (data) {
  console.log(data) // <Buffer hello encrypted!>
})
```

## API

#### `const s = new NoiseSecretStream(isInitiator, [rawStream], [options])`

Make a new stream. `isInitiator` is a boolean indication whether you are the client or the server.
`rawStream` can be set to an underlying transport stream you want to run the noise stream over.

Options include:

```js
{
  pattern: 'XX', // which noise pattern to use
  remotePublicKey, // set if your handshake requires it
  keyPair: { publicKey, secretKey },
  handshake: { // if you want to use an handshake performed elsewhere pass it here
    tx,
    rx,
    handshakeHash,
    publicKey,
    remotePublicKey
  }
}
```

The NoiseSecretStream returned is a Duplex stream that you use as as normal stream, to write/read data from,
except it's payloads are encrypted using the libsodium secretstream.

Note that this uses ed25519 for the handshakes per default.

#### `s.start(rawStream, [options])`

Start a NoiseSecretStream from a rawStream asynchrously.

``` js
const s = new NoiseSecretStream({
  autoStart: false // call start manually
})

// ... do async stuff or destroy the stream

s.start(rawStream, {
  ... options from above
})
```

#### `keyPair = NoiseSecretStream.keyPair([seed])`

Generate a ed25519 key pair.

#### `s.publicKey`

Get the local public key.

#### `s.remotePublicKey`

Get the remote's public key.
Populated after `open` is emitted.

#### `s.handshakeHash`

Get the unique hash of this handshake.
Populated after `open` is emitted.

## License

MIT
