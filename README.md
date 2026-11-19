# quickjs-pkcs11

QuickJS Native PKCS#11 bindings.

## Usage

```ts
import { PKCS11 } from 'quickjs-pkcs11';

const pkcs11 = new PKCS11();
if (pkcs11.isInitialized()) {
    const info = pkcs11.getInfo();
    const tokens = pkcs11.getSlots(false);
    const session = pkcs11.openSession(0);
    if (session !== null) {
        const handles = pkcs11.findObjectsByClass(session, PKCS11.CKO_CERTIFICATE);
        pkcs11.closeSession(session);
    }
}
pkcs11.destroy();
```

The constructor initializes the PKCS#11 library and throws if initialization
fails. `getInfo()` returns parsed library information or `null` if the call
fails. `getSlots(tokenPresent = false)` returns the list of token infos or
`null` if the call fails; pass `true` to return only slots containing a token.
`getTokenInfo(slot)` returns parsed token information for the given slot or
`null` if the call fails. `openSession(slot, rw = false)` opens a session and
returns the session handle or `null` on failure. `closeSession(session)` closes
a session. `findObjectsInit(session, types)`, `findObjects(session, maxCount)`
and `findObjectsFinal(session)` perform object searches. `getAttributeValueSize`
returns attribute value lengths. `isInitialized()` reports whether the instance
is currently initialized.

Without a path, the constructor searches common system library directories for
a filename containing `pkcs11` with the platform extension (`.dylib`, `.so`,
or `.dll`). To specify one or more library paths, use the semicolon-separated
format supported by `quickjs-native.loadLibrary`:

```ts
const pkcs11 = new PKCS11('/path/to/libpkcs11.dylib;/another/libpkcs11.dylib');
```

## Create an executable

After compiling your application's entry point to JavaScript, bundle it with
QuickJS Native:

```shell
npx quickjs-native bundle dist/index.js
```

Executables for all supported targets are written to `release/` by default.
Run `npx quickjs-native help` to see the available options.
