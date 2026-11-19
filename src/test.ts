import { PKCS11 } from './index';

const library = '/Library/Belgium Identity Card/Pkcs11/libbeidpkcs11.dylib';

const pkcs11 = new PKCS11(library);

console.log('Initialized:', pkcs11.isInitialized());
console.log('Libraries:', pkcs11.getLibraries().join(', '));

const info = pkcs11.getInfo();
const safeInfo = info ? { ...info, flags: info.flags.toString() } : null;
console.log('Info:', safeInfo ? JSON.stringify(safeInfo) : null);

const tokens = pkcs11.getSlots(false);
const safeTokens = tokens ? tokens.map(t => ({ ...t, flags: t.flags.toString() })) : null;
console.log('All tokens:', safeTokens ? JSON.stringify(safeTokens) : null);

// Session + find certificates/data on slot 0
const slotIds = pkcs11.getSlotIds(false);
console.log('Slot IDs:', slotIds);

if (slotIds && slotIds.length > 0) {
    const session = pkcs11.openSession(slotIds[0], false);
    console.log('Session:', session);
    if (session !== null) {
        const certs = pkcs11.getCertificates(session);
        console.log('Certificates:', certs ? JSON.stringify(certs, null, '  ') : null);
        const data = pkcs11.getData(session);
        console.log('Data objects:', data ? JSON.stringify(data, null, '  ') : null);
        pkcs11.closeSession(session);
        console.log('Session closed');
    }
}

pkcs11.destroy();
console.log('Destroyed, initialized:', pkcs11.isInitialized());
