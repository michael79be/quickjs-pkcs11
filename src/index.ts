import { loadLibrary, type LoadedNativeLibrary } from 'quickjs-native';
import * as os from 'os';

export const CKR_OK = 0;

/** Native size of CK_ULONG for the loaded library's ABI. */
export type CKULongSize = 4 | 8;

/** Status returned by a Cryptoki function. */
export type CK_RV = number;

export interface CK_VERSION {
    major: number;
    minor: number;
}

/** Library-level information returned by the Cryptoki C_GetInfo function. */
export interface CK_INFO {
    /** Version of the Cryptoki interface supported by the library. */
    cryptokiVersion: CK_VERSION;
    /** Fixed-width UTF-8 identifier of the library manufacturer. */
    manufacturerID: string;
    /** Library-wide CK_FLAGS bitset, kept as bigint to preserve all bits. */
    flags: bigint;
    /** Fixed-width UTF-8 description of the library. */
    libraryDescription: string;
    /** Version of this library implementation. */
    libraryVersion: CK_VERSION;
}

export interface PKCS11Options {
    ckULongSize?: CKULongSize;
}

type PKCS11FunctionDefinitions = {
    C_Initialize: 'number';
    C_Finalize: 'number';
    C_GetInfo: 'number';
};

type PKCS11Functions = LoadedNativeLibrary<PKCS11FunctionDefinitions>;

const defaultCKULongSize: CKULongSize = os.platform === 'win32' ? 4 : 8;
const littleEndian = new Uint8Array(new Uint16Array([1]).buffer)[0] === 1;

const searchDirectories: Record<string, string[]> = {
    darwin: [
        '/Library/Belgium Identity Card/Pkcs11',
        '/Library/Frameworks',
        '/usr/local/lib',
        '/opt/homebrew/lib',
        '/usr/lib'
    ],
    linux: [
        '/usr/local/lib',
        '/usr/local/lib64',
        '/usr/lib',
        '/usr/lib64',
        '/usr/lib/x86_64-linux-gnu',
        '/usr/lib/aarch64-linux-gnu',
        '/usr/lib/i386-linux-gnu',
        '/lib',
        '/lib64'
    ],
    win32: [
        'C:/Windows/System32',
        'C:/Windows/SysWOW64',
        'C:/Program Files',
        'C:/Program Files (x86)'
    ]
};

function align(value: number, alignment: number): number {
    return Math.ceil(value / alignment) * alignment;
}

function getInfoLayout(ckULongSize: CKULongSize) {
    if (ckULongSize !== 4 && ckULongSize !== 8) {
        throw new RangeError('CK_ULONG size must be 4 or 8 bytes.');
    }

    const flagsOffset = align(2 + 32, ckULongSize);
    const descriptionOffset = flagsOffset + ckULongSize;
    const versionOffset = descriptionOffset + 32;

    return {
        flagsOffset,
        descriptionOffset,
        versionOffset,
        size: align(versionOffset + 2, ckULongSize)
    };
}

function readFixedUTF8(buffer: ArrayBuffer, offset: number, length: number): string {
    const bytes = new Uint8Array(buffer, offset, length);
    let end = bytes.length;
    while (end > 0 && (bytes[end - 1] === 0 || bytes[end - 1] === 0x20)) {
        end--;
    }

    let encoded = '';
    for (let index = 0; index < end; index++) {
        encoded += `%${bytes[index].toString(16).padStart(2, '0')}`;
    }
    return decodeURIComponent(encoded);
}

function readUnsigned(buffer: ArrayBuffer, offset: number, length: CKULongSize): bigint {
    const view = new DataView(buffer);
    let value = 0n;
    for (let index = length - 1; index >= 0; index--) {
        const byteIndex = littleEndian ? offset + index : offset + length - index - 1;
        value = (value << 8n) | BigInt(view.getUint8(byteIndex));
    }
    return value;
}

function getLibraryExtension(platform: string): RegExp {
    switch (platform) {
        case 'darwin':
            return /pkcs11.*\.dylib$/i;
        case 'linux':
            return /pkcs11.*\.so(?:\.\d+)*$/i;
        case 'win32':
            return /pkcs11.*\.dll$/i;
        default:
            throw new Error(`Automatic PKCS#11 library discovery is unsupported on ${platform}.`);
    }
}

/** Finds matching PKCS#11 libraries in the platform's common library directories. */
export function findPKCS11Libraries(): string {
    const platform = os.platform;
    const extension = getLibraryExtension(platform);
    const [workingDirectory, cwdError] = os.getcwd();
    if (cwdError !== 0) {
        throw new Error(`Unable to get the current directory (error ${cwdError}).`);
    }

    const directories = [...new Set([workingDirectory, ...searchDirectories[platform]])];
    const found = new Set<string>();
    const scanErrors: string[] = [];

    for (const directory of directories) {
        const [entries, readError] = os.readdir(directory);
        if (readError !== 0) {
            scanErrors.push(`${directory} (error ${readError})`);
            continue;
        }

        for (const entry of entries) {
            if (!extension.test(entry)) {
                continue;
            }

            const separator = directory.endsWith('/') || directory.endsWith('\\') ? '' : '/';
            const path = `${directory}${separator}${entry}`;
            const [fileStat, statError] = os.stat(path);
            if (statError === 0 && fileStat !== null && (fileStat.mode & os.S_IFMT) === os.S_IFREG) {
                found.add(path);
            } else if (statError !== 0) {
                scanErrors.push(`${path} (error ${statError})`);
            }
        }
    }

    if (found.size === 0) {
        const errors = scanErrors.length > 0 ? ` Directory scan errors: ${scanErrors.join('; ')}.` : '';
        throw new Error(
            `No PKCS#11 library matching ${extension} found in: ${directories.join(', ')}.${errors}`
        );
    }

    return [...found].join(';');
}

export function createCKInfoBuffer(ckULongSize: CKULongSize = defaultCKULongSize): ArrayBuffer {
    return new ArrayBuffer(getInfoLayout(ckULongSize).size);
}

export function readCKInfo(
    buffer: ArrayBuffer,
    ckULongSize: CKULongSize = defaultCKULongSize
): CK_INFO {
    const layout = getInfoLayout(ckULongSize);
    if (buffer.byteLength < layout.size) {
        throw new RangeError(`CK_INFO requires at least ${layout.size} bytes.`);
    }

    const view = new DataView(buffer);
    return {
        cryptokiVersion: {
            major: view.getUint8(0),
            minor: view.getUint8(1)
        },
        manufacturerID: readFixedUTF8(buffer, 2, 32),
        flags: readUnsigned(buffer, layout.flagsOffset, ckULongSize),
        libraryDescription: readFixedUTF8(buffer, layout.descriptionOffset, 32),
        libraryVersion: {
            major: view.getUint8(layout.versionOffset),
            minor: view.getUint8(layout.versionOffset + 1)
        }
    };
}

/** Loads a Cryptoki library and exposes the currently implemented PKCS#11 calls. */
export class PKCS11 {
    private readonly ckULongSize: CKULongSize;
    private readonly library: PKCS11Functions;
    private initialized = false;
    private destroyed = false;

    constructor(paths?: string, options: PKCS11Options = {}) {
        this.ckULongSize = options.ckULongSize ?? defaultCKULongSize;
        getInfoLayout(this.ckULongSize);
        this.library = loadLibrary(paths ?? findPKCS11Libraries(), {
            C_Initialize: 'number',
            C_Finalize: 'number',
            C_GetInfo: 'number'
        });
    }

    /** Initializes Cryptoki using the default (null) initialization arguments. */
    C_Initialize(): CK_RV {
        const result = this.library.C_Initialize([null]);
        if (result === CKR_OK) {
            this.initialized = true;
        }
        return result;
    }

    /** Finalizes Cryptoki using the required null reserved argument. */
    C_Finalize(): CK_RV {
        const result = this.library.C_Finalize([null]);
        if (result === CKR_OK) {
            this.initialized = false;
        }
        return result;
    }

    /** Calls C_GetInfo with a caller-provided, ABI-sized CK_INFO buffer. */
    C_GetInfo(info: ArrayBuffer): CK_RV {
        const infoSize = getInfoLayout(this.ckULongSize).size;
        if (info.byteLength < infoSize) {
            throw new RangeError(`C_GetInfo requires a buffer of at least ${infoSize} bytes.`);
        }
        return this.library.C_GetInfo([info]);
    }

    /** Calls C_GetInfo and parses CK_INFO only when the return status is CKR_OK. */
    getInfo(): { result: CK_RV; info: CK_INFO | null } {
        const buffer = createCKInfoBuffer(this.ckULongSize);
        const result = this.C_GetInfo(buffer);
        return {
            result,
            info: result === CKR_OK ? readCKInfo(buffer, this.ckULongSize) : null
        };
    }

    /**
     * Finalizes if this instance initialized Cryptoki, then unloads the library.
     * Throws if C_Finalize returns a status other than CKR_OK.
     */
    destroy(): void {
        if (this.destroyed) {
            return;
        }

        try {
            if (this.initialized) {
                const result = this.C_Finalize();
                if (result !== CKR_OK) {
                    throw new Error(`C_Finalize failed with CK_RV ${result}.`);
                }
            }
        } finally {
            this.library.destroy();
            this.destroyed = true;
        }
    }
}
