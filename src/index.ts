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

interface TokenInfo {
    label: string;
    manufacturerID: string;
    model: string;
    serialNumber: string;
    flags: bigint;
    maxSessionCount: number;
    sessionCount: number;
    maxRwSessionCount: number;
    rwSessionCount: number;
    maxPinLen: number;
    minPinLen: number;
    totalPublicMemory: number;
    freePublicMemory: number;
    totalPrivateMemory: number;
    freePrivateMemory: number;
    hardwareVersion: Version;
    firmwareVersion: Version;
    utcTime: string;
}

interface PKCS11Options {
    ckULongSize?: ULongSize;
}

type PKCS11FunctionDefinitions = {
    C_Initialize: 'number';
    C_Finalize: 'number';
    C_GetInfo: 'number';
    C_GetSlotList: 'number';
    C_GetTokenInfo: 'number';
    C_OpenSession: 'number';
    C_CloseSession: 'number';
    C_FindObjectsInit: 'number';
    C_FindObjects: 'number';
    C_FindObjectsFinal: 'number';
    C_GetAttributeValue: 'number';
};

type PKCS11Functions = LoadedNativeLibrary<PKCS11FunctionDefinitions>;

/** Loads and initializes a Cryptoki library. */
export class PKCS11 {
    private static readonly success = 0;

    /** Object classes */
    public static readonly CKO_DATA = 0x00000000;
    public static readonly CKO_CERTIFICATE = 0x00000001;
    public static readonly CKO_PUBLIC_KEY = 0x00000002;
    public static readonly CKO_PRIVATE_KEY = 0x00000003;
    public static readonly CKO_SECRET_KEY = 0x00000004;

    /** Session flags */
    public static readonly CKF_SERIAL_SESSION = 0x00000001;
    public static readonly CKF_RW_SESSION = 0x00000002;

    /** Attribute types */
    public static readonly CKA_CLASS = 0x00000000;
    public static readonly CKA_TOKEN = 0x00000001;
    public static readonly CKA_PRIVATE = 0x00000002;
    public static readonly CKA_LABEL = 0x00000003;
    public static readonly CKA_VALUE = 0x00000011;
    public static readonly CKA_CERTIFICATE_TYPE = 0x00000080;
    public static readonly CKA_ISSUER = 0x00000081;
    public static readonly CKA_SERIAL_NUMBER = 0x00000082;
    public static readonly CKA_URL = 0x00000089;

    public static readonly CK_UNAVAILABLE_INFORMATION = 0xFFFFFFFF;
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
            C_GetInfo: 'number',
            C_GetSlotList: 'number',
            C_GetTokenInfo: 'number',
            C_OpenSession: 'number',
            C_CloseSession: 'number',
            C_FindObjectsInit: 'number',
            C_FindObjects: 'number',
            C_FindObjectsFinal: 'number',
            C_GetAttributeValue: 'number'
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

    /**
     * Returns the list of slot IDs, or null if C_GetSlotList fails.
     * When tokenPresent is true, only slots containing a token are returned.
     */
    public getSlotIds(tokenPresent: boolean = false): number[] | null {
        const countBuffer = new ArrayBuffer(this.ckULongSize);
        const result = this.library.C_GetSlotList([tokenPresent, null, countBuffer]);
        if (result !== PKCS11.success) {
            return null;
        }

        const count = Number(this.readUnsigned(countBuffer, 0, this.ckULongSize));
        if (count === 0) {
            return [];
        }

        const slotBuffer = new ArrayBuffer(count * this.ckULongSize);
        const listResult = this.library.C_GetSlotList([tokenPresent, slotBuffer, countBuffer]);
        if (listResult !== PKCS11.success) {
            return null;
        }

        const slots: number[] = [];
        for (let index = 0; index < count; index++) {
            slots.push(Number(this.readUnsigned(slotBuffer, index * this.ckULongSize, this.ckULongSize)));
        }
        return slots;
    }

    /**
     * Returns the list of token infos, or null if C_GetSlotList fails.
     * When tokenPresent is true, only slots containing a token are returned.
     */
    getSlots(tokenPresent: boolean = false): TokenInfo[] | null {
        const slotIds = this.getSlotIds(tokenPresent);
        if (slotIds === null) {
            return null;
        }

        const tokens: TokenInfo[] = [];
        for (const slot of slotIds) {
            const tokenInfo = this.getTokenInfo(slot);
            if (tokenInfo !== null) {
                tokens.push(tokenInfo);
            }
        }
        return tokens;
    }

    /**
     * Returns parsed token information for the given slot, or null if C_GetTokenInfo fails.
     */
    getTokenInfo(slot: number): TokenInfo | null {
        const buffer = new ArrayBuffer(this.getTokenInfoLayout().size);
        const result = this.library.C_GetTokenInfo([slot, buffer]);
        return result === PKCS11.success ? this.readTokenInfo(buffer) : null;
    }

    /**
     * Opens a session with the given slot.
     * @param rw - when true, opens a read/write session; otherwise read-only.
     * Returns the session handle, or null if C_OpenSession fails.
     */
    openSession(slot: number, rw: boolean = false): number | null {
        const flags = rw ? PKCS11.CKF_SERIAL_SESSION | PKCS11.CKF_RW_SESSION : PKCS11.CKF_SERIAL_SESSION;
        const sessionBuffer = new ArrayBuffer(this.ckULongSize);
        const result = this.library.C_OpenSession([slot, flags, null, null, sessionBuffer]);
        if (result !== PKCS11.success) {
            return null;
        }
        return Number(this.readUnsigned(sessionBuffer, 0, this.ckULongSize));
    }

    /** Closes the given session. Returns true on success. */
    closeSession(session: number): boolean {
        const result = this.library.C_CloseSession([session]);
        return result === PKCS11.success;
    }

    /**
     * Initializes a search for objects matching the given attribute template.
     * When attributeTypes is empty, all objects are matched.
     * Returns true on success.
     */
    findObjectsInit(session: number, attributeTypes: number[] = [], attributeValues: number[] = []): boolean {
        const count = attributeTypes.length;
        const attributeSize = 3 * this.ckULongSize;
        const templateBuffer = new ArrayBuffer(count * attributeSize);
        const view = new DataView(templateBuffer);

        for (let i = 0; i < count; i++) {
            const offset = i * attributeSize;
            view.setUint32(offset, attributeTypes[i], true); // type
            view.setBigUint64(offset + this.ckULongSize, 0n, true); // pValue = NULL
            view.setBigUint64(offset + 2 * this.ckULongSize, 0n, true); // ulValueLen = 0
        }

        const result = this.library.C_FindObjectsInit([session, templateBuffer, count]);
        return result === PKCS11.success;
    }

    /**
     * Finds objects matching the initialized search template.
     * @param maxCount - maximum number of object handles to return.
     * Returns the list of object handles, or null on failure.
     */
    findObjects(session: number, maxCount: number): number[] | null {
        const objectBuffer = new ArrayBuffer(maxCount * this.ckULongSize);
        const countBuffer = new ArrayBuffer(this.ckULongSize);
        const result = this.library.C_FindObjects([session, objectBuffer, maxCount, countBuffer]);
        if (result !== PKCS11.success) {
            return null;
        }
        const count = Number(this.readUnsigned(countBuffer, 0, this.ckULongSize));
        if (count === 0) {
            return [];
        }
        const objects: number[] = [];
        for (let i = 0; i < count; i++) {
            objects.push(Number(this.readUnsigned(objectBuffer, i * this.ckULongSize, this.ckULongSize)));
        }
        return objects;
    }

    /** Finalizes an object search. Returns true on success. */
    findObjectsFinal(session: number): boolean {
        const result = this.library.C_FindObjectsFinal([session]);
        return result === PKCS11.success;
    }

    /**
     * Retrieves attribute value sizes for an object via C_GetAttributeValue.
     * Returns a map of attribute hex key to value length, or null on failure.
     * Actual data retrieval requires ArrayBuffer pointer support in the FFI.
     */
    getAttributeValueSize(session: number, object: number, attributeTypes: number[]): Record<string, number> | null {
        const count = attributeTypes.length;
        const attributeSize = 3 * this.ckULongSize;
        const templateBuffer = new ArrayBuffer(count * attributeSize);
        const view = new DataView(templateBuffer);

        for (let i = 0; i < count; i++) {
            const offset = i * attributeSize;
            view.setUint32(offset, attributeTypes[i], true); // type
            view.setBigUint64(offset + this.ckULongSize, 0n, true); // pValue = NULL
            view.setBigUint64(offset + 2 * this.ckULongSize, 0n, true); // ulValueLen = 0
        }

        const result = this.library.C_GetAttributeValue([session, object, templateBuffer, count]);
        if (result !== PKCS11.success) {
            return null;
        }

        const sizes: Record<string, number> = {};
        for (let i = 0; i < count; i++) {
            const offset = i * attributeSize;
            const type = attributeTypes[i];
            const key = `0x${type.toString(16).padStart(8, '0')}`;
            const valueLen = Number(view.getBigUint64(offset + 2 * this.ckULongSize, true));
            sizes[key] = valueLen === PKCS11.CK_UNAVAILABLE_INFORMATION ? -1 : valueLen;
        }
        return sizes;
    }

    /**
     * Convenience: finds all certificates (CKO_CERTIFICATE) or data objects (CKO_DATA)
     * in the given session and returns their object handles.
     */
    findObjectsByClass(session: number, objectClass: number = PKCS11.CKO_CERTIFICATE): number[] | null {
        if (!this.findObjectsInit(session, [PKCS11.CKA_CLASS], [])) {
            return null;
        }
        const handles = this.findObjects(session, 16);
        this.findObjectsFinal(session);
        return handles;
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

    private writeUnsigned(buffer: ArrayBuffer, offset: number, value: number | bigint, length: ULongSize): void {
        const view = new DataView(buffer);
        const littleEndian = new Uint8Array(new Uint16Array([1]).buffer)[0] === 1;
        const bigIntValue = BigInt(value);
        for (let index = 0; index < length; index++) {
            const byteIndex = littleEndian ? offset + index : offset + length - index - 1;
            view.setUint8(byteIndex, Number((bigIntValue >> BigInt(index * 8)) & 0xffn));
        }
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

    private getTokenInfoLayout() {
        if (this.ckULongSize !== 4 && this.ckULongSize !== 8) {
            throw new RangeError('CK_ULONG size must be 4 or 8 bytes.');
        }

        const modelOffset = 64;
        const serialNumberOffset = modelOffset + 16;
        const flagsOffset = this.align(serialNumberOffset + 16, this.ckULongSize);

        const ulMaxSessionCountOffset = flagsOffset + this.ckULongSize;
        const ulSessionCountOffset = ulMaxSessionCountOffset + this.ckULongSize;
        const ulMaxRwSessionCountOffset = ulSessionCountOffset + this.ckULongSize;
        const ulRwSessionCountOffset = ulMaxRwSessionCountOffset + this.ckULongSize;
        const ulMaxPinLenOffset = ulRwSessionCountOffset + this.ckULongSize;
        const ulMinPinLenOffset = ulMaxPinLenOffset + this.ckULongSize;
        const ulTotalPublicMemoryOffset = ulMinPinLenOffset + this.ckULongSize;
        const ulFreePublicMemoryOffset = ulTotalPublicMemoryOffset + this.ckULongSize;
        const ulTotalPrivateMemoryOffset = ulFreePublicMemoryOffset + this.ckULongSize;
        const ulFreePrivateMemoryOffset = ulTotalPrivateMemoryOffset + this.ckULongSize;

        const hardwareVersionOffset = ulFreePrivateMemoryOffset + this.ckULongSize;
        const firmwareVersionOffset = hardwareVersionOffset + 2;
        const utcTimeOffset = firmwareVersionOffset + 2;

        return {
            labelOffset: 0,
            manufacturerIDOffset: 32,
            modelOffset,
            serialNumberOffset,
            flagsOffset,
            ulMaxSessionCountOffset,
            ulSessionCountOffset,
            ulMaxRwSessionCountOffset,
            ulRwSessionCountOffset,
            ulMaxPinLenOffset,
            ulMinPinLenOffset,
            ulTotalPublicMemoryOffset,
            ulFreePublicMemoryOffset,
            ulTotalPrivateMemoryOffset,
            ulFreePrivateMemoryOffset,
            hardwareVersionOffset,
            firmwareVersionOffset,
            utcTimeOffset,
            size: this.align(utcTimeOffset + 16, this.ckULongSize)
        };
    }

    private readTokenInfo(buffer: ArrayBuffer): TokenInfo {
        const layout = this.getTokenInfoLayout();
        if (buffer.byteLength < layout.size) {
            throw new RangeError(`CK_TOKEN_INFO requires at least ${layout.size} bytes.`);
        }

        const view = new DataView(buffer);
        return {
            label: this.readFixedUTF8(buffer, layout.labelOffset, 32),
            manufacturerID: this.readFixedUTF8(buffer, layout.manufacturerIDOffset, 32),
            model: this.readFixedUTF8(buffer, layout.modelOffset, 16),
            serialNumber: this.readFixedUTF8(buffer, layout.serialNumberOffset, 16),
            flags: this.readUnsigned(buffer, layout.flagsOffset, this.ckULongSize),
            maxSessionCount: Number(this.readUnsigned(buffer, layout.ulMaxSessionCountOffset, this.ckULongSize)),
            sessionCount: Number(this.readUnsigned(buffer, layout.ulSessionCountOffset, this.ckULongSize)),
            maxRwSessionCount: Number(this.readUnsigned(buffer, layout.ulMaxRwSessionCountOffset, this.ckULongSize)),
            rwSessionCount: Number(this.readUnsigned(buffer, layout.ulRwSessionCountOffset, this.ckULongSize)),
            maxPinLen: Number(this.readUnsigned(buffer, layout.ulMaxPinLenOffset, this.ckULongSize)),
            minPinLen: Number(this.readUnsigned(buffer, layout.ulMinPinLenOffset, this.ckULongSize)),
            totalPublicMemory: Number(this.readUnsigned(buffer, layout.ulTotalPublicMemoryOffset, this.ckULongSize)),
            freePublicMemory: Number(this.readUnsigned(buffer, layout.ulFreePublicMemoryOffset, this.ckULongSize)),
            totalPrivateMemory: Number(this.readUnsigned(buffer, layout.ulTotalPrivateMemoryOffset, this.ckULongSize)),
            freePrivateMemory: Number(this.readUnsigned(buffer, layout.ulFreePrivateMemoryOffset, this.ckULongSize)),
            hardwareVersion: {
                major: view.getUint8(layout.hardwareVersionOffset),
                minor: view.getUint8(layout.hardwareVersionOffset + 1)
            },
            firmwareVersion: {
                major: view.getUint8(layout.firmwareVersionOffset),
                minor: view.getUint8(layout.firmwareVersionOffset + 1)
            },
            utcTime: this.readFixedUTF8(buffer, layout.utcTimeOffset, 16)
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

    private _native(): any {
        return (globalThis as any).native;
    }

    private _libcHandle: number | null = null;
    private _mallocAddr: number | null = null;
    private _memcpyAddr: number | null = null;
    private _freeAddr: number | null = null;

    private _ensureLibc(): boolean {
        if (this._mallocAddr !== null) {
            return true;
        }
        const native = this._native();
        if (!native) {
            return false;
        }
        try {
            const handle = native.dlopen('/usr/lib/libSystem.dylib');
            if (!handle) {
                return false;
            }
            this._libcHandle = handle;
            this._mallocAddr = native.dlsym(handle, 'malloc');
            this._memcpyAddr = native.dlsym(handle, 'memcpy');
            this._freeAddr = native.dlsym(handle, 'free');
            return true;
        } catch {
            return false;
        }
    }

    private _malloc(size: number): number | null {
        if (!this._ensureLibc() || !this._mallocAddr) {
            return null;
        }
        const native = this._native();
        const ret = native.invoke(this._mallocAddr, [size], 'number');
        return ret || null;
    }

    private _memcpy(dst: number, src: number, size: number): void {
        if (!this._ensureLibc() || !this._memcpyAddr) {
            return;
        }
        const native = this._native();
        native.invoke(this._memcpyAddr, [dst, src, size], 'number');
    }

    private _free(ptr: number): void {
        if (!this._ensureLibc() || !this._freeAddr) {
            return;
        }
        const native = this._native();
        native.invoke(this._freeAddr, [ptr], 'number');
    }
}
