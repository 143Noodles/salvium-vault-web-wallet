
export enum ViewState {
  WELCOME = 'WELCOME',
  CREATE_WALLET = 'CREATE_WALLET',
  RESTORE_WALLET = 'RESTORE_WALLET',
  VERIFY_SEED = 'VERIFY_SEED',
  SET_PASSWORD = 'SET_PASSWORD',
  SCANNING = 'SCANNING',
  LOGIN = 'LOGIN',
  DASHBOARD = 'DASHBOARD'
}

export enum TabState {
  ASSETS = 'ASSETS',
  SEND = 'SEND',
  RECEIVE = 'RECEIVE',
  STAKE = 'STAKE',
  HISTORY = 'HISTORY',
  SETTINGS = 'SETTINGS'
}

export interface Transaction {
  id: string;
  type: 'in' | 'out';
  amount: number;
  date: string;
  status: 'pending' | 'completed' | 'failed';
  hash: string;
  address: string;
}

export interface WalletData {
  address: string;
  balance: number;
  unlockedBalance: number;
  name: string;
  transactions: Transaction[];
  isSyncing: boolean;
  syncProgress: number;
}

// Encrypted wallet storage format
export interface EncryptedWallet {
  address: string;
  encryptedSeed: string;  // AES-GCM encrypted seed
  iv: string;             // Initialization vector for decryption
  salt: string;           // Salt used for key derivation
  pub_viewKey: string;    // Public view key (not secret)
  pub_spendKey: string;   // Public spend key (not secret)
  createdAt: number;      // Timestamp
  height?: number;        // Last scanned block height
  keyImagesCsv?: string;  // CSP v6: Cached key images for spent detection (avoids Phase 1b rescan)
}