import { encrypt, decrypt, arrayBufferToBase64, base64ToArrayBuffer } from './CryptoService';

const BACKUP_VERSION = 1;
const IDB_NAME = 'salvium_vault_cache_v2';
const IDB_STORE = 'wallet_cache';
const IDB_VERSION = 1;

function openCacheDB(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(IDB_NAME, IDB_VERSION);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result);
        request.onupgradeneeded = (event: IDBVersionChangeEvent) => {
            const db = (event.target as IDBOpenDBRequest).result;
            if (!db.objectStoreNames.contains(IDB_STORE)) {
                db.createObjectStore(IDB_STORE, { keyPath: 'key' });
            }
        };
    });
}

async function saveToIndexedDB(key: string, value: string): Promise<void> {
    const db = await openCacheDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(IDB_STORE, 'readwrite');
        const store = tx.objectStore(IDB_STORE);
        const request = store.put({ key, value });
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve();
        tx.oncomplete = () => db.close();
    });
}

async function loadFromIndexedDB(key: string): Promise<string | null> {
    try {
        const db = await openCacheDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(IDB_STORE, 'readonly');
            const store = tx.objectStore(IDB_STORE);
            const request = store.get(key);
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result?.value || null);
            tx.oncomplete = () => db.close();
        });
    } catch {
        return null;
    }
}

export interface BackupData {
    version: number;
    timestamp: number;
    wallet: any;
    walletCacheHex?: string;
    contacts: any[];
    settings: {
        autoLockEnabled: boolean;
        autoLockMinutes: number;
    };
    walletCacheCompressed?: string;
}

async function compressString(data: string): Promise<string> {
    const stream = new Blob([data]).stream();
    const compressedStream = stream.pipeThrough(new CompressionStream('gzip'));
    const response = new Response(compressedStream);
    const buffer = await response.arrayBuffer();
    return arrayBufferToBase64(buffer);
}

async function decompressString(base64Data: string): Promise<string> {
    const buffer = base64ToArrayBuffer(base64Data);
    const stream = new Blob([buffer]).stream();
    const decompressedStream = stream.pipeThrough(new DecompressionStream('gzip'));
    const response = new Response(decompressedStream);
    return await response.text();
}

interface EncryptedBackup {
    encrypted: string;
    iv: string;
    salt: string;
}

export async function generateBackup(password: string): Promise<Blob> {
    const walletJson = localStorage.getItem('salvium_wallet');
    if (!walletJson) {
        throw new Error('No wallet found to backup');
    }
    const wallet = JSON.parse(walletJson);

    let walletCacheHex: string | undefined;
    if (wallet.address) {
        const cacheKey = `wallet_cache_${wallet.address}`;
        const cachedData = await loadFromIndexedDB(cacheKey);
        if (cachedData) {
            walletCacheHex = cachedData;
        }
    } else {
        console.warn('[BackupService] Cannot load wallet cache: address missing');
    }

    let walletCacheCompressed: string | undefined;
    if (walletCacheHex) {
        try {
            walletCacheCompressed = await compressString(walletCacheHex);
            walletCacheHex = undefined;
        } catch (e) {
            console.warn('[BackupService] Compression failed, falling back to raw hex', e);
        }
    }

    const contactsJson = localStorage.getItem('salvium_contacts');
    const contacts = contactsJson ? JSON.parse(contactsJson) : [];

    const settingsJson = localStorage.getItem('salvium_settings');
    const settings = settingsJson ? JSON.parse(settingsJson) : {
        autoLockEnabled: true,
        autoLockMinutes: 15
    };

    const backupData: BackupData = {
        version: BACKUP_VERSION,
        timestamp: Date.now(),
        wallet,
        walletCacheHex,
        walletCacheCompressed,
        contacts,
        settings
    };

    const backupJson = JSON.stringify(backupData);
    const { encrypted, iv, salt } = await encrypt(backupJson, password);

    const encryptedBackup: EncryptedBackup = { encrypted, iv, salt };
    return new Blob([JSON.stringify(encryptedBackup)], { type: 'application/octet-stream' });
}

export async function downloadBackup(password: string): Promise<void> {
    const blob = await generateBackup(password);
    const filename = `salvium.vault`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

export async function parseBackup(file: File, password: string): Promise<BackupData> {
    const fileContent = await file.text();

    let encryptedBackup: EncryptedBackup;
    try {
        encryptedBackup = JSON.parse(fileContent);
    } catch {
        throw new Error('Invalid backup file format');
    }

    if (!encryptedBackup.encrypted || !encryptedBackup.iv || !encryptedBackup.salt) {
        throw new Error('Invalid backup file structure');
    }

    let backupJson: string;
    try {
        backupJson = await decrypt(encryptedBackup.encrypted, encryptedBackup.iv, encryptedBackup.salt, password);
    } catch {
        throw new Error('Incorrect password or corrupted backup file');
    }

    let backupData: BackupData;
    try {
        backupData = JSON.parse(backupJson);
    } catch {
        throw new Error('Corrupted backup data');
    }

    if (!backupData.version || backupData.version > BACKUP_VERSION) {
        throw new Error('Unsupported backup version. Please update the app.');
    }

    if (!backupData.wallet) {
        throw new Error('Backup file is missing wallet data');
    }

    return backupData;
}

export async function restoreFromBackup(backupData: BackupData): Promise<void> {
    localStorage.setItem('salvium_wallet', JSON.stringify(backupData.wallet));
    localStorage.setItem('salvium_wallet_created', 'true');

    let walletCacheHex: string | undefined = backupData.walletCacheHex;

    if (backupData.walletCacheCompressed) {
        try {
            walletCacheHex = await decompressString(backupData.walletCacheCompressed);
        } catch (e) {
            console.error('[BackupService] Decompression failed:', e);
        }
    }

    if (!walletCacheHex) {
        walletCacheHex = backupData.wallet.cachedOutputsHex;
    }

    if (walletCacheHex && walletCacheHex.length > 0) {
        try {
            const address = backupData.wallet.address;
            if (!address) {
                console.warn('[BackupService] Cannot restore cache: backup is missing wallet address');
                localStorage.setItem('salvium_initial_scan_complete', 'false');
                return;
            }
            const cacheKey = `wallet_cache_${address}`;
            await saveToIndexedDB(cacheKey, walletCacheHex);
            localStorage.setItem('salvium_initial_scan_complete', 'false');
        } catch (e) {
            console.error('[BackupService] Failed to save cache to IndexedDB:', e);
            localStorage.setItem('salvium_initial_scan_complete', 'false');
        }
    } else {
        localStorage.setItem('salvium_initial_scan_complete', 'false');
    }

    if (backupData.contacts && Array.isArray(backupData.contacts)) {
        localStorage.setItem('salvium_contacts', JSON.stringify(backupData.contacts));
    }

    if (backupData.settings) {
        localStorage.setItem('salvium_settings', JSON.stringify(backupData.settings));
    }
}

