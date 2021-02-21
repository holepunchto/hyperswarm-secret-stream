# noise-secret-stream

Secret stream backed by Noise and libsodium's secretstream

```
npm install noise-secret-stream
```

## Usage

``` js
const NoiseSecretStream = require('noise-secret-stream')

const a = new NoiseSecretStream(true)
const b = new NoiseSecretStream(false)

a.pipe(b).pipe(a)

a.send(Buffer.from('hello'))

b.on('message', function (message) {
  console.log(message) // <Buffer hello>
})
```

## API

#### `const s = new NoiseSecretStream(isInitiator, [options])`

Make a new stream. `isInitiator` is a boolean indication whether you are the client or the server.
Pipe this over a tcp/utp stream or similar to another noise secret stream instance.

Options include:

```js
{
  keyPair: { publicKey, secretKey }
}
```

#### `keyPair = NoiseSecretStream.keyPair([seed])`

Generate a key pair.

#### `flushed = s.send(message)`

Send a message. Returns `true` if the stream was flushed, `false` otherwards.

#### `s.on('message', message)`

Emitted when a message is received.

## License

MIT
