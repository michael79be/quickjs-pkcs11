import { PKCS11 } from '../dist/index.js';

const library = '/Library/Belgium Identity Card/Pkcs11/libbeidpkcs11.dylib';

const pkcs11 = new PKCS11(library);

console.log('Initialized:', pkcs11.isInitialized());
console.log('Libraries:', pkcs11.getLibraries().join(', '));

const info = pkcs11.getInfo();
const safeInfo = info ? { ...info, flags: info.flags.toString() } : null;
console.log('Info:', safeInfo ? JSON.stringify(safeInfo) : null);

const slots = pkcs11.getSlotList(false);
console.log('All slots:', slots);

const tokenSlots = pkcs11.getSlotList(true);
console.log('Token slots:', tokenSlots);

pkcs11.destroy();
console.log('Destroyed, initialized:', pkcs11.isInitialized());
