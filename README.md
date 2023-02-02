# xk6-tls

A k6 extension for sending strings via TLS

## Build

To build a `k6` binary with this plugin, first ensure you have the prerequisites:

- [Go toolchain](https://go101.org/article/go-toolchain.html)
- Git

Then:

1. Install `xk6`:

  ```shell
  go install github.com/k6io/xk6/cmd/xk6@latest
  ```

2. Build the binary:

  ```shell
  xk6 build master \
    --with github.com/vsofin/xk6-raw-http
  ```

## Example 1

```javascript
import worker from 'k6/x/raw-http';
import { check } from 'k6';

const conn = worker.connectTCP('host:port');

export default function () {
    worker.writeTCP(conn, 'Say Hello\n');
    let res = String.fromCharCode(...worker.readTCP(conn, 1024))
    check (res, {
        'verify ag tag': (res) => res.includes('Hello')
    });
    worker.closeTCP(conn);
}
```

## Example 2

```javascript
import worker from 'k6/x/raw-http';
import { check } from 'k6';

const conn = worker.connectTCP('host:port');

export default function () {
    const conn = worker.connectTLS('host:port');
}
```
