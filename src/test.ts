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

const tokenOnly = pkcs11.getSlots(true);
const safeTokenOnly = tokenOnly ? tokenOnly.map(t => ({ ...t, flags: t.flags.toString() })) : null;
console.log('Token-only tokens:', safeTokenOnly ? JSON.stringify(safeTokenOnly) : null);

// Session + find objects on slot 0
const slotIds = pkcs11.getSlotIds(false);
console.log('Slot IDs:', slotIds);

if (slotIds && slotIds.length > 0) {
    for (const rw of [false, true]) {
        const session = pkcs11.openSession(slotIds[0], rw);
        console.log(`Session (rw=${rw}):`, session);
        if (session !== null) {
            const certHandles = pkcs11.findObjectsByClass(session, PKCS11.CKO_CERTIFICATE);
            console.log(`Certificate handles (rw=${rw}):`, certHandles);
            pkcs11.closeSession(session);
            console.log(`Session closed (rw=${rw})`);
        }
    }
}

pkcs11.destroy();
console.log('Destroyed, initialized:', pkcs11.isInitialized());
