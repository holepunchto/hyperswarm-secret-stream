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

#### `const s = NoiseSecretStream.async(async func)`

Create a NoiseSecretStream from an async contructor.
The async function passed is expected to return the arguments that should be passed to the constructor
as an array, ie:

``` js
const s = NoiseSecretStream.async(async function () {
  const socket = await connectAsyncToSocket(...)
  const opts = ...
  return [true, socket, opts] // [isInitiator, rawStream, opts]
})
```

#### `keyPair = NoiseSecretStream.keyPair([seed])`

Generate a key pair.

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
