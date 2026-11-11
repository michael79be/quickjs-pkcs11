const lib = native.dlopen('/Library/Belgium Identity Card/Pkcs11/libbeidpkcs11.dylib') ?? 0;
if (0 === lib) {
    throw new Error('Could not load pkcs11 library');
}

const pkcs11: { [key: string]: (args: unknown[]) => unknown } = {
    C_Initialize: () => {},
    C_GetInfo: () => {}
};

const func: { [key: string]: number | null } = {};
Object.keys(pkcs11).forEach((name) => {
    func[name] = native.dlsym(lib, name);
    if (null === func[name]) {
        throw new Error(`Function ${name} not found`);
    }
    pkcs11[name] = (args) => {
        if (null === func[name]) {
            return null;
        }
        return native.invoke(func[name], args);
    }
});

const init = pkcs11.C_Initialize([]);
console.log(`init: ${init}`);

const b = ' ';
// 38 instead of 32 to round to up to 8 bytes (2 + 32 + 8 = 42 + 6 = 48 % 8 = 0)
const infos = b.repeat(2) + b.repeat(32) + b.repeat(8) + b.repeat(38) + b.repeat(2);
pkcs11.C_GetInfo([infos]);
console.log(`infos: ${infos}`);

const cryptoki = `${infos.charCodeAt(0)}.${infos.charCodeAt(1)}`;
console.log(`cryptoki: ${cryptoki}`);

const manufacturer = infos.substring(2, 2 + 32);
console.log(`manufacturer: ${manufacturer}`);

const description = infos.substring(42, 42 + 39);
console.log(`description: ${description}`);

const version = `${infos.charCodeAt(80)}.${infos.charCodeAt(81)}`;
console.log(`version: ${version}`);
