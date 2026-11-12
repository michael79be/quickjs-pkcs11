# quickjs-pkcs11

QuickJS Native PKCS#11 bindings.

## Usage

```ts
import { PKCS11 } from 'quickjs-pkcs11';

const pkcs11 = new PKCS11();
const initResult = pkcs11.C_Initialize();
const { result: infoResult, info } = pkcs11.getInfo();
pkcs11.destroy();
```

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
