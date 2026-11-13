import { loadLibrary, type LoadedNativeLibrary } from 'quickjs-native';
import * as os from 'os';

type ULongSize = 4 | 8;

interface Version {
    major: number;
    minor: number;
}

interface PKCS11Info {
    cryptokiVersion: Version;
    manufacturerID: string;
    flags: bigint;
    libraryDescription: string;
    libraryVersion: Version;
}

interface PKCS11Options {
    ckULongSize?: ULongSize;
}

type PKCS11FunctionDefinitions = {
    C_Initialize: 'number';
    C_Finalize: 'number';
    C_GetInfo: 'number';
};

type PKCS11Functions = LoadedNativeLibrary<PKCS11FunctionDefinitions>;

/** Loads and initializes a Cryptoki library. */
export class PKCS11 {
    private static readonly success = 0;
    private static readonly searchDirectories: Record<string, string[]> = {
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

    private readonly ckULongSize: ULongSize;
    private readonly libraries: string[];
    private readonly library: PKCS11Functions;
    private initialized = false;
    private destroyed = false;

    constructor(paths?: string, options: PKCS11Options = {}) {
        this.ckULongSize = options.ckULongSize ?? (os.platform === 'win32' ? 4 : 8);
        this.getInfoLayout();
        const libraryPaths = paths ?? this.findPKCS11Libraries();
        this.libraries = libraryPaths.split(';');
        this.library = loadLibrary(libraryPaths, {
            C_Initialize: 'number',
            C_Finalize: 'number',
            C_GetInfo: 'number'
        });

        const result = this.library.C_Initialize([null]);
        if (result !== PKCS11.success) {
            this.library.destroy();
            throw new Error(`C_Initialize failed with CK_RV ${result}.`);
        }
        this.initialized = true;
    }

    /** Returns parsed library information, or null if C_GetInfo fails. */
    getInfo(): PKCS11Info | null {
        const buffer = new ArrayBuffer(this.getInfoLayout().size);
        const result = this.library.C_GetInfo([buffer]);
        return result === PKCS11.success ? this.readInfo(buffer) : null;
    }

    getLibraries(): string[] {
        return [...this.libraries];
    }

    isInitialized(): boolean {
        return this.initialized;
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
                const result = this.library.C_Finalize([null]);
                if (result === PKCS11.success) {
                    this.initialized = false;
                } else {
                    throw new Error(`C_Finalize failed with CK_RV ${result}.`);
                }
            }
        } finally {
            this.library.destroy();
            this.destroyed = true;
        }
    }

    private align(value: number, alignment: number): number {
        return Math.ceil(value / alignment) * alignment;
    }

    private getInfoLayout() {
        if (this.ckULongSize !== 4 && this.ckULongSize !== 8) {
            throw new RangeError('CK_ULONG size must be 4 or 8 bytes.');
        }

        const flagsOffset = this.align(2 + 32, this.ckULongSize);
        const descriptionOffset = flagsOffset + this.ckULongSize;
        const versionOffset = descriptionOffset + 32;

        return {
            flagsOffset,
            descriptionOffset,
            versionOffset,
            size: this.align(versionOffset + 2, this.ckULongSize)
        };
    }

    private readFixedUTF8(buffer: ArrayBuffer, offset: number, length: number): string {
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

    private readUnsigned(buffer: ArrayBuffer, offset: number, length: ULongSize): bigint {
        const view = new DataView(buffer);
        const littleEndian = new Uint8Array(new Uint16Array([1]).buffer)[0] === 1;
        let value = 0n;
        for (let index = length - 1; index >= 0; index--) {
            const byteIndex = littleEndian ? offset + index : offset + length - index - 1;
            value = (value << 8n) | BigInt(view.getUint8(byteIndex));
        }
        return value;
    }

    private readInfo(buffer: ArrayBuffer): PKCS11Info {
        const layout = this.getInfoLayout();
        if (buffer.byteLength < layout.size) {
            throw new RangeError(`CK_INFO requires at least ${layout.size} bytes.`);
        }

        const view = new DataView(buffer);
        return {
            cryptokiVersion: {
                major: view.getUint8(0),
                minor: view.getUint8(1)
            },
            manufacturerID: this.readFixedUTF8(buffer, 2, 32),
            flags: this.readUnsigned(buffer, layout.flagsOffset, this.ckULongSize),
            libraryDescription: this.readFixedUTF8(buffer, layout.descriptionOffset, 32),
            libraryVersion: {
                major: view.getUint8(layout.versionOffset),
                minor: view.getUint8(layout.versionOffset + 1)
            }
        };
    }

    private getLibraryExtension(platform: string): RegExp {
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

    private findPKCS11Libraries(): string {
        const platform = os.platform;
        const extension = this.getLibraryExtension(platform);
        const [workingDirectory, cwdError] = os.getcwd();
        if (cwdError !== 0) {
            throw new Error(`Unable to get the current directory (error ${cwdError}).`);
        }

        const directories = [
            ...new Set([workingDirectory, ...(PKCS11.searchDirectories[platform] ?? [])])
        ];
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
}
