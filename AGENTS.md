# quickjs-pkcs11

QuickJS Native PKCS#11 bindings.

## Building

```shell
npm run build
```

Builds `dist/index.js` (the package) and `dist/types/index.d.ts`.

## Testing

Compile and bundle `src/test.ts` into a standalone executable:

```shell
npx rollup --config rollup.config.ts --configPlugin typescript --input src/test.ts
npx quickjs-native bundle dist/test.js --output-dir /tmp/kilo-pkcs11-test
/tmp/kilo-pkcs11-test/test-macos-universal
```

The test connects to the Belgium eID PKCS#11 library and reports slots. It expects slot `0` (the reader) and token information when a card is inserted.

## Developing

- `src/index.ts` — PKCS#11 bindings (`C_Initialize`, `C_Finalize`, `C_GetInfo`, `C_GetSlotList`, `C_GetTokenInfo`, `C_OpenSession`, `C_CloseSession`, `C_FindObjectsInit`, `C_FindObjects`, `C_FindObjectsFinal`, `C_GetAttributeValue`).
- `src/test.ts` — test script (untracked, not in package.json) for Belgium eID library.
- `tsconfig.json` — `include: ["src/index.ts"]`, so `tsc` type-checks only the package source.
- `package.json` — `main: ./dist/index.js`, `types: ./dist/types/index.d.ts`.

Do not edit `package.json` unless adding scripts or dependencies. `npm run build` is pinned to the rollup config (`rollup.config.ts`) which defaults input to `src/index.ts`.

## Running with QuickJS Native

After bundling, run any target executable:

```shell
# macOS (universal)
/path/to/bundle/test-macos-universal

# macOS Intel
/path/to/bundle/test-macos-intel

# Windows
/path/to/bundle/test.exe

# Linux
/path/to/bundle/test-linux
```

## Conventions

- Imports use `import { loadLibrary } from 'quickjs-native'` and FFI return types are `'number' | 'string' | 'boolean'`.
- Arguments to native functions are passed as an array.
- `ArrayBuffer` pointers are used for output buffers (e.g. slot lists).
- `CK_ULONG` values are read via `readUnsigned()` honoring `ckULongSize` (4 on Windows, 8 elsewhere).
- No comments added unless requested.
