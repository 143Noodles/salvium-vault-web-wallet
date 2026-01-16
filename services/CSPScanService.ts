/**
 * CSP Scan Service
 * 
 * Integrates CSPScanner with the wallet for blockchain scanning.
 * Uses Compact Scan Protocol for fast parallel scanning via web workers.
 * 
 * v3.5.20-csv-fix: Fixed worker init - pass CSV string directly to init_view_only_with_map
 * Same pattern as Phase 1: multiple workers process batches independently,
 * results fed back to main wallet.
 */

// Note: walletService is imported lazily inside methods to avoid circular dependency
// at module initialization time

/**
 * Adaptive worker count based on device capabilities
 * Scales based on available RAM and CPU cores
 */
function getOptimalWorkerCount(): number {
  const ua = navigator.userAgent || '';
  const isAndroid = /Android/i.test(ua);

  // Use device memory if available (Chrome/Edge only)
  const deviceMemory = (navigator as any).deviceMemory; // GB

  if (deviceMemory) {
    // Android WebView/emulators often report optimistic memory/cores; cap workers to avoid OOM.
    if (isAndroid) {
      if (deviceMemory <= 2) return 1;
      return 2;
    }

    // Memory-based scaling (same for mobile and desktop)
    if (deviceMemory >= 8) return 6;
    if (deviceMemory >= 6) return 4;
    if (deviceMemory >= 4) return 3;
    if (deviceMemory >= 2) return 2;
    return 1; // Very low memory devices
  }

  // Fallback: CPU cores (Safari doesn't report memory)
  const cores = navigator.hardwareConcurrency || 4;

  // Android: conservative cap even without deviceMemory
  if (isAndroid) return Math.min(2, Math.max(1, Math.floor(cores / 4)));

  // Use half the cores, capped at 6, min 2
  return Math.min(6, Math.max(2, Math.floor(cores / 2)));
}

/**
 * Yields to the browser's render cycle for smooth UI updates
 */
function yieldToUI(): Promise<void> {
  return new Promise(resolve => {
    requestAnimationFrame(() => setTimeout(resolve, 0));
  });
}

// Time-slicing: track frame start time and yield when budget exceeded
const FRAME_BUDGET_MS = 12; // Target ~60fps (16.67ms) with headroom
let frameStartTime = 0;

function startFrame(): void {
  frameStartTime = performance.now();
}

function shouldYield(): boolean {
  return performance.now() - frameStartTime > FRAME_BUDGET_MS;
}

async function yieldIfNeeded(): Promise<void> {
  if (shouldYield()) {
    await yieldToUI();
    startFrame();
  }
}

// Phase 2 Worker management
interface Phase2WorkerState {
  worker: Worker;
  id: number;
  ready: boolean;
  busy: boolean;
  currentBatchId: number | null;
}

// Cached WASM for Phase 2 workers
let phase2WasmBinary: ArrayBuffer | null = null;
let phase2PatchedJsCode: string | null = null;

// Scanner callback types
export interface ScanProgress {
  progress: number;  // 0-1 (phase-specific, kept for compatibility)
  scannedBlocks: number;
  totalBlocks: number;
  completedChunks: number;
  totalChunks: number;
  viewTagMatches: number;
  bytesReceived: number;
  blocksPerSecond: number;
  // v5.1.7: Startup optimization fields
  phase?: string;
  message?: string;
  subaddressCount?: number;
  totalSubaddresses?: number;
  scanRate?: number;
  // v5.2.8: Unified progress display
  overallProgress?: number;  // 0-1 (weighted across ALL phases)
  percentage?: number;       // 0-100 (for display convenience)
  transactionsFound?: number; // Running counter of found transactions
  statusMessage?: string;    // User-friendly status message
}

export interface ScanResult {
  success: boolean;
  matches: any[];
  matchCount: number;
  blocksScanned: number;
  blocksPerSecond: number;
  matchedChunks?: number[];  // Chunk start heights with matches
  outputsFound?: number;     // Outputs found after phase 2
  error?: string;
  keyImagesCsv?: string;     // Key images CSV for persistence (enables single-pass on next scan)
}

// Global CSPScanner class loaded from script
declare global {
  interface Window {
    CSPScanner: any;
  }
}

class CSPScanService {
  private static instance: CSPScanService;
  private scanner: any = null;
  private isScanning: boolean = false;
  private scriptLoaded: boolean = false;

  // v5.42.0: Track last processed heights for incremental stake return optimization
  private lastProcessedStakeReturnHeight: number = 0;
  private registeredStakeInfo: boolean = false;  // Track if stake_return_info was registered this session

  private constructor() { }

  static getInstance(): CSPScanService {
    if (!CSPScanService.instance) {
      CSPScanService.instance = new CSPScanService();
    }
    return CSPScanService.instance;
  }

  /**
   * Load the CSPScanner script
   */
  private async loadScript(): Promise<void> {
    if (this.scriptLoaded) return;

    return new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = '/vault/wallet/CSPScanner.js?v=5.49.1';
      script.async = true;

      script.onload = () => {
        this.scriptLoaded = true;
        resolve();
      };

      script.onerror = () => {
        reject(new Error('Failed to load CSPScanner script'));
      };

      document.head.appendChild(script);
    });
  }

  /**
   * Get current network height from daemon
   */
  async getNetworkHeight(): Promise<number> {
    try {
      // Try our proxy endpoint
      const response = await fetch('/vault/api/daemon/info');
      if (response.ok) {
        const data = await response.json();
        return data.height || 0;
      }
    } catch (e) {
      console.warn('[CSPScanService] Failed to get height from proxy:', e);
    }

    // Fallback: direct RPC (may fail due to CORS)
    try {
      const response = await fetch('https://seed01.salvium.io:19081/get_info', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: '0', method: 'get_info' })
      });
      if (response.ok) {
        const data = await response.json();
        return data.result?.height || 0;
      }
    } catch (e) {
      console.warn('[CSPScanService] Failed to get height from direct RPC:', e);
    }

    return 0;
  }

  /**
   * Fetch stake return heights from server for coinbase filtering
   * This dramatically reduces false positives by only passing through
   * coinbase outputs at heights where stake returns actually occur.
   */
  private async fetchStakeReturnHeights(minHeight: number, maxHeight: number): Promise<number[]> {
    try {
      const response = await fetch(`/vault/api/wallet/stake-return-heights?min=${minHeight}&max=${maxHeight}`);
      if (!response.ok) {
        throw new Error(`Failed to fetch stake return heights: ${response.status}`);
      }
      const data = await response.json();
      if (data.success && Array.isArray(data.heights)) {
        return data.heights;
      }
      return [];
    } catch (e) {
      console.warn('[CSPScanService] Proxy fetchStakeReturnHeights error, trying direct RPC:', e);

      // Fallback: direct RPC to seed node
      try {
        const response = await fetch(`https://seed01.salvium.io:19081/get_stake_return_heights?min_height=${minHeight}&max_height=${maxHeight}`);
        if (!response.ok) throw new Error(`Direct RPC failed: ${response.status}`);

        const data = await response.json();
        if (data.status === 'OK' && Array.isArray(data.heights)) {
          return data.heights;
        }
      } catch (rpcErr) {
        console.warn('[CSPScanService] Direct RPC fetchStakeReturnHeights failed:', rpcErr);
      }

      return [];
    }
  }

  /**
   * Start CSP scanning
   * @param cachedKeyImagesCsv - Optional cached key images CSV from previous scan (enables single-pass spent detection)
   */
  async startScan(
    startHeight: number,
    endHeight: number,
    onProgress?: (progress: ScanProgress) => void,
    onMatch?: (match: any) => void,
    cachedKeyImagesCsv?: string,
    isIncremental: boolean = false
  ): Promise<ScanResult> {
    if (this.isScanning) {
      return { success: false, matches: [], matchCount: 0, blocksScanned: 0, blocksPerSecond: 0, error: 'Scan already in progress', keyImagesCsv: '' };
    }

    // Load script if needed
    await this.loadScript();

    if (!window.CSPScanner) {
      return { success: false, matches: [], matchCount: 0, blocksScanned: 0, blocksPerSecond: 0, error: 'CSPScanner not available', keyImagesCsv: '' };
    }

    // Get keys from wallet (dynamic import to avoid circular dependency)
    const { walletService } = await import('./WalletService');
    const wallet = walletService.getWallet();
    if (!wallet) {
      return { success: false, matches: [], matchCount: 0, blocksScanned: 0, blocksPerSecond: 0, error: 'Wallet not initialized', keyImagesCsv: '' };
    }

    // Step 1A: Precompute subaddresses (v5.1.7 Optimization)
    // This moves the heavy operation out of startup and into the scan loading phase
    if (onProgress) onProgress({
      phase: '1A',
      totalBlocks: 0,
      scannedBlocks: 0,
      viewTagMatches: 0,
      blocksPerSecond: 0,
      subaddressCount: 0,
      totalSubaddresses: 20000,
      message: 'Generating subaddress keys...',
      progress: 0,
      completedChunks: 0,
      totalChunks: 0,
      bytesReceived: 0,
      // Calibrated: Scanner init is ~0.1% of total time
      overallProgress: 0.001,
      percentage: 0,
      transactionsFound: 0,
      statusMessage: 'Preparing wallet...'
    });

    // CLI-style lazy expansion: Start with minimal subaddresses (CLI default: 200)
    // The wallet2::expand_subaddresses() will grow the map on demand when matches found
    const TOTAL_SUBADDRESSES = 200;  // CLI wallet default (replaces 20k upfront)

    try {
      if (typeof wallet.precompute_subaddresses === 'function') {
        if (typeof (window as any).DEBUG) console.log(`[CSPScanService] Generating ${TOTAL_SUBADDRESSES} subaddresses (CLI default, lazy expansion enabled)...`);
        wallet.precompute_subaddresses(0, TOTAL_SUBADDRESSES);
        if (typeof (window as any).DEBUG) console.log(`[CSPScanService] ✅ Generated ${TOTAL_SUBADDRESSES} subaddresses (expand_subaddresses handles growth)`);
      }
    } catch (e) {
      console.warn('[CSPScanService] precompute_subaddresses failed (might be old WASM):', e);
    }

    let viewSecretKey: string = '';
    let kViewIncoming: string = '';
    let sViewBalance: string = '';
    let publicSpendKey: string = '';
    let keyImagesCsv: string = '';

    try {
      viewSecretKey = wallet.get_secret_view_key();
      publicSpendKey = wallet.get_public_spend_key();
    } catch (e) {
      console.error('[CSPScanService] Failed to get keys:', e);
      return { success: false, matches: [], matchCount: 0, blocksScanned: 0, blocksPerSecond: 0, error: 'Failed to get keys', keyImagesCsv: '' };
    }

    // CSP v6: Key image spent detection (for OUT tx discovery)
    // Use cached key images if provided (enables single-pass spent detection on reload)
    if (cachedKeyImagesCsv && cachedKeyImagesCsv.length >= 64) {
      keyImagesCsv = cachedKeyImagesCsv;
    } else {
      try {
        if (typeof wallet.get_key_images_csv === 'function') {
          keyImagesCsv = wallet.get_key_images_csv() || '';
        }
      } catch (e) {
        console.warn('[CSPScanService] Failed to get key images (OUT txs may be missed):', e);
        keyImagesCsv = '';
      }
    }

    try {
      if (typeof wallet.get_carrot_k_view_incoming === 'function') {
        kViewIncoming = wallet.get_carrot_k_view_incoming();
      }
    } catch (e) {
      console.warn('[CSPScanService] Failed to get Carrot key (Carrot txs may be missed):', e);
    }

    try {
      if (typeof wallet.get_carrot_s_view_balance === 'function') {
        sViewBalance = wallet.get_carrot_s_view_balance();
      }
    } catch (e) {
      console.warn('[CSPScanService] Failed to get Carrot s_view_balance (internal enotes may be missed):', e);
    }

    if (!viewSecretKey || viewSecretKey.length !== 64) {
      return { success: false, matches: [], matchCount: 0, blocksScanned: 0, blocksPerSecond: 0, error: 'Invalid view secret key', keyImagesCsv: '' };
    }

    const ua = navigator.userAgent || '';
    const isAndroid = /Android/i.test(ua);
    const maxWorkerCount = isIncremental ? Math.max(1, Math.floor(getOptimalWorkerCount() / 2)) : getOptimalWorkerCount();
    const initialWorkerCount = Math.max(1, Math.min(maxWorkerCount, isAndroid ? 2 : 2));

    // Get return addresses for RETURN tx detection
    let returnAddressesCsv: string = '';
    try {
      if (typeof wallet.get_return_addresses_csv === 'function') {
        returnAddressesCsv = wallet.get_return_addresses_csv();
        if (returnAddressesCsv) {
          const count = returnAddressesCsv.split(',').filter(s => s.length === 64).length;
          if (typeof (wallet as any).add_return_addresses === 'function' && count > 0) {
            (wallet as any).add_return_addresses(returnAddressesCsv);
          }
        }
      }
    } catch (e) {
      // RETURN tx detection disabled
    }

    // Get subaddress map (after adding return addresses)
    let subaddressMapCsv: string = '';
    try {
      if (typeof wallet.get_subaddress_spend_keys_csv === 'function') {
        subaddressMapCsv = wallet.get_subaddress_spend_keys_csv();
      }
    } catch (e) {
      console.warn('[CSPScanService] Failed to get subaddress map (ownership verification disabled):', e);
    }

    // Fetch stake return heights to filter coinbase passthrough (eliminates 65% false positives)
    let stakeReturnHeights: number[] = [];
    try {
      stakeReturnHeights = await this.fetchStakeReturnHeights(startHeight, endHeight);
    } catch (e) {
      console.warn('[CSPScanService] Failed to fetch stake return heights (coinbase filtering disabled):', e);
    }

    this.isScanning = true;
    const startTime = performance.now();

    try {
      // Create scanner
      this.scanner = new window.CSPScanner({
        viewSecretKey,
        publicSpendKey,
        kViewIncoming: kViewIncoming || '',
        sViewBalance: sViewBalance || '',
        keyImagesCsv,
        subaddressMapCsv,
        returnAddressesCsv,
        stakeReturnHeights,
        apiBaseUrl: '/vault',
        // Auto-tuning: start small, ramp up to max as device allows
        autoTune: true,
        maxWorkerCount,
        initialWorkerCount,
        workerCount: maxWorkerCount,
        // Android WebView: avoid bundle streaming (high peak memory) and use smaller batches.
        useBundleMode: !isAndroid,
        batchSize: isAndroid ? 6 : 20,
        chunkSize: 1000,
        onProgress: (data: any) => {
          const elapsed = (performance.now() - startTime) / 1000;
          // Phase 1 (ViewTag Scan) is 1-76% of overall progress (based on timing calibration)
          const phase1Progress = data.progress || 0;
          const overallProgress = 0.01 + (0.75 * phase1Progress);
          const progress: ScanProgress = {
            progress: phase1Progress,
            scannedBlocks: data.scannedBlocks || 0,
            totalBlocks: data.totalBlocks || 0,
            completedChunks: data.completedChunks || 0,
            totalChunks: data.totalChunks || 0,
            viewTagMatches: data.viewTagMatches || 0,
            bytesReceived: data.bytesReceived || 0,
            blocksPerSecond: data.scannedBlocks / elapsed,
            phase: '1',
            message: `Scanning blocks (${data.viewTagMatches || 0} matches)`,
            // v5.2.8: Unified progress
            overallProgress,
            percentage: Math.min(100, Math.round(overallProgress * 100)),
            transactionsFound: 0,
            statusMessage: 'Scanning blockchain...'
          };
          onProgress?.(progress);
        },
        onMatch: (data: any) => {
          // Matches are aggregated - no per-match logging for performance
          onMatch?.(data);
        },
        onError: (data: any) => {
          console.error('[CSPScanService] Scan error:', data);
        }
      });

      // Initialize workers
      await this.scanner.init();

      // Run scan (Phase 1: View tag scanning)
      const result = await this.scanner.scan(startHeight, endHeight);

      const matchedChunks: number[] = result.matchedChunks || [];
      const allMatches: any[] = result.matches || [];

      // Phase 2: Targeted rescan - fetch and ingest sparse transactions
      let outputsFound = 0;
      if (matchedChunks.length > 0 && allMatches.length > 0) {
        // IMPORTANT: Do not silently continue on Phase 2 failures.
        // A partial Phase 2 ingest leads to missing transactions.
        outputsFound = await this.targetedRescan(wallet, matchedChunks, allMatches, onProgress, startHeight, endHeight, isIncremental);
      }

      // Phase 2b: RETURN Transaction Discovery
      // After Phase 2 ingests outgoing transfers, check for new return addresses
      if (!returnAddressesCsv && typeof wallet.get_return_addresses_csv === 'function') {
        const newReturnAddressesCsv = wallet.get_return_addresses_csv();
        if (newReturnAddressesCsv && newReturnAddressesCsv.length >= 64) {
          const returnAddressCount = newReturnAddressesCsv.split(',').filter((s: string) => s.length === 64).length;
          console.log(`[CSPScanService] Phase 2b: Found ${returnAddressCount} return addresses, rescanning...`);

          if (onProgress) {
            onProgress({
              progress: 0.95, phase: '2b', message: 'Scanning for RETURN transactions...',
              scannedBlocks: 0, totalBlocks: 0, completedChunks: 0, totalChunks: 0,
              viewTagMatches: 0, bytesReceived: 0, blocksPerSecond: 0,
              overallProgress: 0.95, percentage: 95, transactionsFound: outputsFound,
              statusMessage: 'Scanning for RETURN transactions...'
            });
          }

          this.scanner.updateReturnAddresses(newReturnAddressesCsv);
          const returnResult = await this.scanner.scan(startHeight, endHeight);
          const returnMatches = returnResult.matches || [];
          const returnMatchedChunks = returnResult.matchedChunks || [];

          if (returnMatchedChunks.length > 0 && returnMatches.length > 0) {
            const alreadyProcessed = new Set(matchedChunks);
            const newChunks = returnMatchedChunks.filter((c: number) => !alreadyProcessed.has(c));

            if (newChunks.length > 0) {
              const newMatches = returnMatches.filter((m: any) => {
                const chunkStart = Math.floor(m.height / 720) * 720;
                return newChunks.includes(chunkStart);
              });

              if (newMatches.length > 0) {
                const returnOutputsFound = await this.targetedRescan(wallet, newChunks, newMatches, onProgress, startHeight, endHeight, true);
                outputsFound += returnOutputsFound;
                console.log(`[CSPScanService] Phase 2b: Ingested ${returnOutputsFound} RETURN outputs`);
              }
            }
          }
        }
      }

      // ================================================================
      // Phase 1b: Spent Output Discovery (Privacy-Preserving)
      // ================================================================
      // Key images only exist AFTER Phase 2 ingests outputs.
      // We download the server's spent index and filter locally.
      // Server never learns which key images belong to us (privacy preserved).
      // ================================================================
      // Report progress for Spent Discovery phase (97-100%)
      if (onProgress) {
        onProgress({
          progress: 0,
          phase: '4',
          message: 'Checking spent outputs...',
          scannedBlocks: 0,
          totalBlocks: 0,
          completedChunks: 0,
          totalChunks: 0,
          viewTagMatches: 0,
          bytesReceived: 0,
          blocksPerSecond: 0,
          overallProgress: 0.97,
          percentage: 97,
          transactionsFound: outputsFound,
          statusMessage: 'Checking spent outputs...'
        });
      }
      try {
        const initialHadKeyImages = !!(keyImagesCsv && keyImagesCsv.length >= 64);
        const canGetKeyImages = typeof wallet.get_key_images_csv === 'function';

        if (!initialHadKeyImages && canGetKeyImages) {
          // Refresh key images if we found new outputs
          const refreshedKeyImagesCsv = wallet.get_key_images_csv() || '';
          if (refreshedKeyImagesCsv.length >= 64) {
            const keyImagesList = refreshedKeyImagesCsv.split(',').filter(Boolean);
            const kiCount = keyImagesList.length;

            // Build a Set of our key images for O(1) lookup
            const ourKeyImages = new Set(keyImagesList);

            // Download spent index in chunks and filter locally
            const spentMatches: Array<{ ki: string, tx: string, h: number, idx: number }> = [];
            let currentHeight = startHeight;
            const BATCH_SIZE = 50000; // Download in batches to avoid huge responses
            const heightRange = endHeight - startHeight;

            const spentIndexStart = performance.now();

            while (currentHeight <= endHeight) {
              try {
                // Report smooth progress within spent discovery phase (97-100%)
                if (onProgress && heightRange > 0) {
                  const spentProgress = Math.min(1, (currentHeight - startHeight) / heightRange);
                  const overallProgress = 0.97 + (0.03 * spentProgress);
                  onProgress({
                    progress: spentProgress,
                    phase: '4',
                    message: `Checking spent outputs... ${Math.round(spentProgress * 100)}%`,
                    scannedBlocks: currentHeight - startHeight,
                    totalBlocks: heightRange,
                    completedChunks: 0,
                    totalChunks: 0,
                    viewTagMatches: 0,
                    bytesReceived: 0,
                    blocksPerSecond: 0,
                    overallProgress,
                    percentage: Math.round(overallProgress * 100),
                    transactionsFound: outputsFound,
                    statusMessage: 'Checking spent outputs...'
                  });
                }

                const response = await fetch('/vault/api/wallet/get-spent-index', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ start_height: currentHeight, max_items: BATCH_SIZE })
                });

                if (!response.ok) {
                  console.warn(`[CSPScanService] Spent index fetch failed at height ${currentHeight}`);
                  break;
                }

                const data = await response.json();
                if (!data.items || data.items.length === 0) {
                  break; // No more data
                }

                // Filter locally - server never sees which ones are ours
                for (const item of data.items) {
                  if (ourKeyImages.has(item.ki)) {
                    spentMatches.push(item);
                  }
                }

                // Move to next batch
                currentHeight = data.next_height || (currentHeight + 1000);

                // Check if we've processed everything
                if (data.remaining === 0) {
                  break;
                }
              } catch (e) {
                console.warn(`[CSPScanService] Spent index batch error:`, e);
                break;
              }
            }

            const spentIndexMs = performance.now() - spentIndexStart;

            if (spentMatches.length > 0) {
              // ================================================================
              // DIRECT SPENT MARKING (v5.24.0)
              // Instead of re-ingesting spending TXs (which don't contain our outputs),
              // directly mark the key images as spent in the wallet.
              // ================================================================
              if (typeof (wallet as any).mark_spent_by_key_images === 'function') {
                // Build CSV: "ki1:height1,ki2:height2,..."
                const spentCsv = spentMatches.map(s => `${s.ki}:${s.h}`).join(',');

                try {
                  const result = (wallet as any).mark_spent_by_key_images(spentCsv);
                  const parsed = JSON.parse(result);
                } catch (e) {
                  console.error('[CSPScanService] Failed to mark spent by key images:', e);
                }
              } else {
                console.warn('[CSPScanService] mark_spent_by_key_images not available - WASM needs update');
              }
            }
          }
        }
      } catch (e) {
        console.warn('[CSPScanService] Phase 1b spent discovery failed (continuing):', e);
      }

      // Final summary logged by targetedRescan

      // Update wallet height after scan
      if (wallet && endHeight > 0) {
        try {
          wallet.set_wallet_height(endHeight);
        } catch (e) {
          console.warn('[CSPScanService] Failed to update wallet height:', e);
        }
      }

      // Get final key images CSV for persistence (enables single-pass scanning on next reload)
      let finalKeyImagesCsv = keyImagesCsv;
      try {
        if (typeof wallet.get_key_images_csv === 'function') {
          finalKeyImagesCsv = wallet.get_key_images_csv() || '';
        }
      } catch (e) {
        console.warn('[CSPScanService] Failed to get final key images:', e);
      }

      // Report 100% completion
      if (onProgress) {
        onProgress({
          progress: 1,
          phase: 'complete',
          message: 'Scan complete',
          scannedBlocks: endHeight - startHeight,
          totalBlocks: endHeight - startHeight,
          completedChunks: 0,
          totalChunks: 0,
          viewTagMatches: 0,
          bytesReceived: 0,
          blocksPerSecond: 0,
          overallProgress: 1.0,
          percentage: 100,
          transactionsFound: outputsFound,
          statusMessage: 'Scan complete'
        });
      }

      return {
        success: true,
        matches: result.matches || [],
        matchCount: result.matchCount || 0,
        blocksScanned: result.blocksScanned || 0,
        blocksPerSecond: result.blocksPerSecond || 0,
        matchedChunks,
        outputsFound,
        keyImagesCsv: finalKeyImagesCsv  // Return for persistence
      };

    } catch (e) {
      console.error('[CSPScanService] Scan failed:', e);
      return {
        success: false,
        matches: [],
        matchCount: 0,
        blocksScanned: 0,
        blocksPerSecond: 0,
        error: `${e}`,
        keyImagesCsv: ''
      };
    } finally {
      this.isScanning = false;
      if (this.scanner) {
        this.scanner.destroy();
        this.scanner = null;
      }
    }
  }

  /**
   * Stop current scan
   */
  stopScan(): void {
    if (this.scanner) {
      this.scanner.abort();
    }
  }

  /**
   * Check if scanning is in progress
   */
  isScanningInProgress(): boolean {
    return this.isScanning;
  }

  /**
   * Reset incremental scan state (call when wallet is reloaded/changed)
   * v5.42.0: Added for incremental stake return optimization
   */
  resetIncrementalState(): void {
    this.lastProcessedStakeReturnHeight = 0;
    this.registeredStakeInfo = false;
  }

  /**
   * Reset cancellation flag (call before starting a new scan)
   * v5.42.1: Added to fix missing method error
   */
  resetCancellation(): void {
    // Currently a no-op since we don't have a cancellation token system yet
    // This method exists to satisfy the WalletContext.tsx call
  }

  /**
   * Cancel any ongoing scan (alias for stopScan + state reset)
   * v5.46.1: Added to fix "cancelScan is not a function" error during wallet reset
   */
  cancelScan(): void {
    this.stopScan();
    this.isScanning = false;
  }

  /**
   * Phase 2: Targeted rescan - fetch sparse transactions for matched chunks
   * and ingest them into the wallet using Pipelined Sequential ingestion.
   *
   * v10.9: Pipelined Sequential Ingestion
   * - Producer: Fetches batches (50 chunks) in parallel (concurrency 6)
   * - Consumer: Ingests batches continuously on Main Thread
   * This overlaps Network IO with CPU processing, utilizing 100% of single core
   * without the complexity/overhead of worker state synchronization.
   * With -O3 WASM, this should be very fast.
   * 
   * v5.42.0: Added scanStartHeight/scanEndHeight for incremental stake return optimization
   */
  private async targetedRescan(
    wallet: any,
    matchedChunks: number[],
    allMatches: any[],
    onProgress?: (progress: ScanProgress) => void,
    scanStartHeight?: number,
    scanEndHeight?: number,
    isIncremental: boolean = false
  ): Promise<number> {
    if (!wallet || typeof wallet.ingest_sparse_transactions !== 'function') {
      console.warn('[CSPScanService] ingest_sparse_transactions not available');
      return 0;
    }

    const { walletService } = await import('./WalletService');
    const Module = walletService.getModule();
    if (!Module) return 0;

    // 1. Prepare Match Data
    const matchesByChunk = new Map<number, number[]>();
    for (const match of allMatches) {
      const chunkStart = match.chunkStart ?? Math.floor((match.block_height || match.height || 0) / 1000) * 1000;
      if (!matchesByChunk.has(chunkStart)) matchesByChunk.set(chunkStart, []);
      const txIndex = match.tx_idx ?? match.tx ?? match.txIndex ?? 0;
      const indices = matchesByChunk.get(chunkStart)!;
      if (!indices.includes(txIndex)) indices.push(txIndex);
    }
    const sortedChunks = [...matchedChunks].sort((a, b) => a - b);

    const allStakeHeights: number[] = [];
    const allAuditHeights: number[] = [];
    let totalOutputsFound = 0;

    // 2. Pipelined Execution
    const FETCH_CONCURRENCY = 6;
    const fetchQueue = [...sortedChunks];
    const ingestQueue: Array<{ start: number, data: Uint8Array }> = [];
    let isFetching = true;

    // Producer Loop (Async)
    const producer = async () => {
      const activeFetches: Promise<void>[] = [];
      try {
        while (fetchQueue.length > 0 || activeFetches.length > 0) {
          // Fill concurrency slots
          while (fetchQueue.length > 0 && activeFetches.length < FETCH_CONCURRENCY) {
            // Backpressure: if ingest queue is too full, wait to avoid OOM
            if (ingestQueue.length > 50) {
              await new Promise(r => setTimeout(r, 50)); // Reduced from 100ms
              continue;
            }

            // Adaptive Batch Size:
            // - Incremental/Background: 10 chunks (keep UI responsive, yield often)
            // - Initial/Restore: 50 chunks (maximize throughput, UI freezing acceptable)
            const batchSize = isIncremental ? 10 : 50;
            const chunks = fetchQueue.splice(0, batchSize);
            const reqChunks = chunks.map(c => ({ startHeight: c, indices: matchesByChunk.get(c) || [] })).filter(c => c.indices.length > 0);

            if (reqChunks.length === 0) continue;

            const p = fetch('/vault/api/wallet/batch-sparse-txs', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ chunks: reqChunks })
            }).then(async r => {
              if (r.ok) {
                const buf = new Uint8Array(await r.arrayBuffer());
                ingestQueue.push({ start: chunks[0], data: buf });
              } else {
                console.warn(`[CSPScanService] Fetch failed: ${r.status}`);
              }
            }).catch(e => {
              console.warn('[CSPScanService] Fetch error', e);
            });

            activeFetches.push(p);
            p.finally(() => {
              const idx = activeFetches.indexOf(p);
              if (idx !== -1) activeFetches.splice(idx, 1);
            });
          }

          if (activeFetches.length > 0) {
            await Promise.race(activeFetches);
          } else if (fetchQueue.length === 0) {
            break;
          }
        }
      } finally {
        isFetching = false;
      }
    };

    // Start Producer
    producer();

    // Consumer Loop - process batches in HEIGHT ORDER for correct spent detection
    let processedChunks = 0;
    const totalChunks = sortedChunks.length;
    const startTime = performance.now();

    // Build expected batch starts (every 50 chunks, or whatever was batched)
    const BATCH_SIZE = isIncremental ? 10 : 50;
    const expectedBatchStarts: number[] = [];
    for (let i = 0; i < sortedChunks.length; i += BATCH_SIZE) {
      expectedBatchStarts.push(sortedChunks[i]);
    }

    // Track expected next batch to process (for in-order ingestion)
    let nextExpectedBatchIdx = 0;
    const pendingTasks = new Map<number, { start: number, data: Uint8Array }>();
    const processedBatches = new Set<number>(); // Track processed batches to prevent duplicates

    while (isFetching || ingestQueue.length > 0 || pendingTasks.size > 0) {
      // Move items from ingestQueue to pendingTasks map (keyed by batch start height)
      while (ingestQueue.length > 0) {
        const task = ingestQueue.shift()!;
        pendingTasks.set(task.start, task);
      }

      // Try to process the next expected batch
      const expectedBatchStart = expectedBatchStarts[nextExpectedBatchIdx];
      if (expectedBatchStart === undefined) {
        // All batches processed
        break;
      }

      if (!pendingTasks.has(expectedBatchStart)) {
        // Next batch not ready yet, wait (reduced from 20ms to 5ms for faster response)
        await new Promise(r => setTimeout(r, 5));
        continue;
      }

      const task = pendingTasks.get(expectedBatchStart)!;
      pendingTasks.delete(expectedBatchStart);
      nextExpectedBatchIdx++;

      // Prevent duplicate processing
      if (processedBatches.has(expectedBatchStart)) {
        console.warn(`[CSPScanService] Phase 2: DUPLICATE BATCH DETECTED! Skipping batch at height ${expectedBatchStart}`);
        // Update wallet status
        if (onProgress) {
          processedChunks += BATCH_SIZE; // Approximation
          const currentScanned = Math.min(processedChunks * 1000, totalChunks * 1000); // Rough estimate
          // In Phase 2, we are at 100% progress generally, but this keeps the UI active
          // or we could map it to 99%
        }

        // YIELD TO MAIN THREAD (Crucial for incremental scan smoothness)
        // For incremental scans, we force a yield after every batch to let the UI render.
        if (isIncremental) {
          await new Promise(r => setTimeout(r, 10)); // 10ms yield
        }
      }
      processedBatches.add(expectedBatchStart);

      if (task.data.length > 4) {
        try {
          // Parse batch response format: [ChunkCount:4] + [StartHeight:4][DataSize:4][SparseData]...
          const view = new DataView(task.data.buffer, task.data.byteOffset, task.data.byteLength);
          const chunkCount = view.getUint32(0, true);
          let offset = 4;

          if (isIncremental) {
            // Incremental: process chunks with time-slicing for smooth UI
            startFrame();
            for (let c = 0; c < chunkCount && offset + 8 <= task.data.length; c++) {
              const chunkStartHeight = view.getUint32(offset, true);
              offset += 4;
              const dataSize = view.getUint32(offset, true);
              offset += 4;

              if (dataSize > 4 && offset + dataSize <= task.data.length) {
                const sparseData = task.data.subarray(offset, offset + dataSize);

                const ptr = Module.allocate_binary_buffer(sparseData.length);
                if (ptr) {
                  Module.HEAPU8.set(sparseData, ptr);
                  const resJson = wallet.ingest_sparse_transactions(ptr, sparseData.length, chunkStartHeight, true);
                  Module.free_binary_buffer(ptr);

                  const res = JSON.parse(resJson);
                  if (res.success) {
                    totalOutputsFound += res.txs_matched || 0;
                    if (res.stake_heights) allStakeHeights.push(...res.stake_heights);
                    if (res.audit_heights) allAuditHeights.push(...res.audit_heights);
                  }
                }
                offset += dataSize;
                await yieldIfNeeded();
              } else {
                offset += dataSize;
              }
            }
          } else {
            // Full scan: merge chunks for throughput
            let totalTxCountV2 = 0;
            const txRecordPartsV2: Uint8Array[] = [];
            let firstHeightV2 = 0;

            let totalTxCountSPR = 0;
            const txRecordPartsSPR: Uint8Array[] = [];
            let firstHeightSPR = 0;
            let sprVersion = 0x34;  // Default to SPR4, but will be updated if SPR5 is detected

            for (let c = 0; c < chunkCount && offset + 8 <= task.data.length; c++) {
              const chunkStartHeight = view.getUint32(offset, true);
              offset += 4;
              const dataSize = view.getUint32(offset, true);
              offset += 4;

              if (dataSize > 4 && offset + dataSize <= task.data.length) {
                const sparseData = task.data.subarray(offset, offset + dataSize);
                const chunkView = new DataView(sparseData.buffer, sparseData.byteOffset, sparseData.byteLength);

                // Check for SPRx magic header (S, P, R, followed by version digit)
                const isSPRx =
                  sparseData.length >= 8 &&
                  sparseData[0] === 0x53 && // 'S'
                  sparseData[1] === 0x50 && // 'P'
                  sparseData[2] === 0x52 && // 'R'
                  (sparseData[3] === 0x33 || sparseData[3] === 0x34 || sparseData[3] === 0x35);

                const txCount = isSPRx ? chunkView.getUint32(4, true) : chunkView.getUint32(0, true);
                const recordOffset = isSPRx ? 8 : 4;

                if (isSPRx) {
                  if (sparseData[3] > sprVersion) sprVersion = sparseData[3];
                  if (firstHeightSPR === 0) firstHeightSPR = chunkStartHeight;
                  totalTxCountSPR += txCount;
                  if (sparseData.length > recordOffset) {
                    txRecordPartsSPR.push(sparseData.subarray(recordOffset));
                  }
                } else {
                  if (firstHeightV2 === 0) firstHeightV2 = chunkStartHeight;
                  totalTxCountV2 += txCount;
                  if (sparseData.length > recordOffset) {
                    txRecordPartsV2.push(sparseData.subarray(recordOffset));
                  }
                }
                offset += dataSize;
              } else {
                offset += dataSize;
              }
            }

            // Build merged buffer(s) and ingest
            if (totalTxCountV2 > 0 && txRecordPartsV2.length > 0) {
              let totalRecordBytes = 0;
              for (const part of txRecordPartsV2) totalRecordBytes += part.length;

              const mergedBuffer = new Uint8Array(4 + totalRecordBytes);
              new DataView(mergedBuffer.buffer).setUint32(0, totalTxCountV2, true);
              let writeOffset = 4;
              for (const part of txRecordPartsV2) {
                mergedBuffer.set(part, writeOffset);
                writeOffset += part.length;
              }

              const ptr = Module.allocate_binary_buffer(mergedBuffer.length);
              if (ptr) {
                Module.HEAPU8.set(mergedBuffer, ptr);
                const resJson = wallet.ingest_sparse_transactions(ptr, mergedBuffer.length, firstHeightV2 || 0, true);
                Module.free_binary_buffer(ptr);

                const res = JSON.parse(resJson);
                if (res.success) {
                  totalOutputsFound += res.txs_matched || 0;
                  if (res.stake_heights) allStakeHeights.push(...res.stake_heights);
                  if (res.audit_heights) allAuditHeights.push(...res.audit_heights);
                } else {
                  console.warn(`[CSPScanService] Phase 2: V2 batch ingest failed:`, res);
                }
              }
            }

            if (totalTxCountSPR > 0 && txRecordPartsSPR.length > 0) {
              let totalRecordBytes = 0;
              for (const part of txRecordPartsSPR) totalRecordBytes += part.length;

              const mergedBuffer = new Uint8Array(8 + totalRecordBytes);
              mergedBuffer[0] = 0x53; // S
              mergedBuffer[1] = 0x50; // P
              mergedBuffer[2] = 0x52; // R
              mergedBuffer[3] = sprVersion;
              new DataView(mergedBuffer.buffer).setUint32(4, totalTxCountSPR, true);
              let writeOffset = 8;
              for (const part of txRecordPartsSPR) {
                mergedBuffer.set(part, writeOffset);
                writeOffset += part.length;
              }

              const ptr = Module.allocate_binary_buffer(mergedBuffer.length);
              if (ptr) {
                Module.HEAPU8.set(mergedBuffer, ptr);
                const resJson = wallet.ingest_sparse_transactions(ptr, mergedBuffer.length, firstHeightSPR || 0, true);
                Module.free_binary_buffer(ptr);

                const res = JSON.parse(resJson);
                if (res.success) {
                  totalOutputsFound += res.txs_matched || 0;
                  if (res.stake_heights) allStakeHeights.push(...res.stake_heights);
                  if (res.audit_heights) allAuditHeights.push(...res.audit_heights);
                } else {
                  console.warn(`[CSPScanService] Phase 2: SPR batch ingest failed:`, res);
                }
              }
            }
          }
        } catch (e) {
          console.error('[CSPScanService] Ingest error', e);
        }
      } else {
        console.warn(`[CSPScanService] Phase 2: Batch ${nextExpectedBatchIdx} has no data (${task.data.length} bytes)`);
      }
      processedChunks += BATCH_SIZE;
      if (processedChunks > totalChunks) processedChunks = totalChunks;

      // Progress Update - Phase 2 (Fetch+Ingest) is 76-90% of overall progress
      // (based on timing: 69.19s fetch+ingest out of 106.45s targeted rescan = 65%)
      // Phase 3b (stake returns) handles 90-97%
      if (onProgress) {
        const phase2Progress = processedChunks / totalChunks;
        const overallProgress = 0.76 + (0.14 * phase2Progress);

        onProgress({
          progress: phase2Progress,
          phase: '2',
          message: `Ingesting transactions (found ${totalOutputsFound})...`,
          scannedBlocks: 0,
          totalBlocks: 0,
          completedChunks: processedChunks,
          totalChunks: totalChunks,
          viewTagMatches: allMatches.length,
          bytesReceived: 0,
          blocksPerSecond: 0,
          // v5.2.8: Unified progress
          overallProgress,
          percentage: Math.round(overallProgress * 100),
          transactionsFound: totalOutputsFound,
          statusMessage: 'Processing transactions...'
        });
      }

      if (!isIncremental && processedChunks % 5 === 0) {
        await yieldToUI();
      }
    }

    // ================================================================
    // PHASE 3: Stake Return Processing (v5.42.1 INCREMENTAL OPTIMIZATION)
    // ================================================================
    // Problem: Previously, we fetched ALL stake returns on EVERY scan, even for
    // single-block updates. This took ~16-20s to process 1217 return heights.
    //
    // Solution: 
    // - Phase 3a (register stake info): ALWAYS run - it's fast (just API call + parse)
    //   and we need to catch new stakes made during the session
    // - Phase 3b (fetch return blocks): INCREMENTAL - only fetch newly matured returns
    // ================================================================
    const CARROT_FORK_HEIGHT = 334750;
    const STAKE_RETURN_OFFSET = 21601;

    // Determine if this is an incremental scan (small range, e.g., 1-10 blocks)
    const scanRange = (scanEndHeight || 0) - (scanStartHeight || 0);
    const isIncrementalScan = scanRange <= 100;

    // Phase 3a: Register stake return info (ALWAYS run - catches new stakes)
    // This is fast (~100ms) - just an API call and CSV parsing
    // We need to run this every time to catch:
    // 1. New stakes made by the user during this session
    // 2. New stakes from server's updated stake cache
    try {
      const stakeResponse = await fetch('/vault/api/wallet/stake-cache?v=5.1.6');
      if (stakeResponse.ok) {
        const stakeData = await stakeResponse.json();
        if (stakeData.success && stakeData.stakes && Array.isArray(stakeData.stakes)) {
          const postCarrotStakes = stakeData.stakes.filter((s: any) =>
            s.block_height >= CARROT_FORK_HEIGHT &&
            s.first_key_image && s.first_key_image.length === 64 && !s.first_key_image.match(/^0+$/) &&
            s.stake_output_key && s.stake_output_key.length === 64 &&
            s.return_address && s.return_address.length === 64 && !s.return_address.match(/^0+$/)
          );

          if (postCarrotStakes.length > 0) {
            if (typeof wallet.register_stake_return_info === 'function') {
              const stakesCsv = postCarrotStakes
                .map((s: any) => `${s.first_key_image}:${s.stake_output_key}:${s.return_address}`)
                .join(',');
              wallet.register_stake_return_info(stakesCsv);
            }
            // Add post-Carrot stake heights to allStakeHeights
            const serverStakeHeights = postCarrotStakes.map((s: any) => s.block_height);
            const existingSet = new Set(allStakeHeights);
            for (const h of serverStakeHeights) {
              if (!existingSet.has(h)) allStakeHeights.push(h);
            }
          }
          this.registeredStakeInfo = true;
        }
      }
    } catch (e: any) {
      console.warn(`[CSPScanService] 🎰 Phase 3a failed:`, e?.message || e);
    }

    // Phase 3b: Fetch stake return blocks (INCREMENTAL OPTIMIZATION)
    if (allStakeHeights.length > 0) {
      try {
        const networkHeight = await this.getNetworkHeight();

        if (isIncrementalScan && this.lastProcessedStakeReturnHeight > 0) {
          const returnHeightsInRange = allStakeHeights
            .map(h => h + STAKE_RETURN_OFFSET)
            .filter(returnH =>
              returnH >= (scanStartHeight || 0) &&
              returnH <= (scanEndHeight || networkHeight)
            );

          if (returnHeightsInRange.length > 0) {
            const stakeHeightsToProcess = returnHeightsInRange.map(rh => rh - STAKE_RETURN_OFFSET);
            // Phase 3b runs from ~90% to ~97% (based on timing: 35.91s / 106.45s ≈ 34% of targeted rescan)
            const stakeReturnsFound = await this.fetchStakeReturnsSparse(wallet, Module, stakeHeightsToProcess, networkHeight, onProgress, 0.90, 0.07);
            if (stakeReturnsFound > 0) totalOutputsFound += stakeReturnsFound;
          }
        } else {
          // Phase 3b runs from ~90% to ~97% (based on timing: 35.91s / 106.45s ≈ 34% of targeted rescan)
          const stakeReturnsFound = await this.fetchStakeReturnsSparse(wallet, Module, allStakeHeights, networkHeight, onProgress, 0.90, 0.07);
          if (stakeReturnsFound > 0) totalOutputsFound += stakeReturnsFound;
        }

        // Update last processed height
        this.lastProcessedStakeReturnHeight = scanEndHeight || networkHeight;
      } catch (e: any) {
        console.error(`[CSPScanService] ❌ Phase 3b failed:`, e?.message || e);
      }
    }

    // Phase 3c: AUDIT returns (unlock at +7201 blocks, ~1 week)
    if (allAuditHeights.length > 0) {
      try {
        const networkHeight = await this.getNetworkHeight();
        const auditReturnsFound = await this.fetchAuditReturnsSparse(wallet, Module, allAuditHeights, networkHeight);
        if (auditReturnsFound > 0) totalOutputsFound += auditReturnsFound;
      } catch (e: any) {
        console.error(`[CSPScanService] ❌ Phase 3c failed:`, e?.message || e);
      }
    }

    return totalOutputsFound;
  }

  /**
   * Fallback: Process sequentially if workers fail
   * OPTIMIZED: Large batches (1500 TXs) + minimal yielding for maximum speed
   */
  /**
   * Fallback: Process sequentially if workers fail
   * SPEED MODE: Large batches (500 TXs) + minimal yielding for maximum throughput
   */
  private async processSequentially(
    wallet: any,
    Module: any,
    allTxEntries: Array<{ height: number; txData: Uint8Array }>,
    allStakeHeights: number[],
    allAuditHeights: number[],
    onProgress: ((progress: ScanProgress) => void) | undefined,
    sortedChunks: number[],
    totalBytes: number,
    allMatches: any[]
  ): Promise<number> {
    let totalOutputsFound = 0;

    const BATCH_SIZE = 500;
    const batches: Array<{ height: number; txData: Uint8Array }>[] = [];
    for (let i = 0; i < allTxEntries.length; i += BATCH_SIZE) {
      batches.push(allTxEntries.slice(i, i + BATCH_SIZE));
    }

    let completed = 0;
    startFrame();
    for (const batch of batches) {
      let totalSize = 0;
      for (const entry of batch) totalSize += entry.txData.length;

      const mergedBuffer = new Uint8Array(4 + totalSize);
      new DataView(mergedBuffer.buffer).setUint32(0, batch.length, true);

      let offset = 4;
      for (const entry of batch) {
        mergedBuffer.set(entry.txData, offset);
        offset += entry.txData.length;
      }

      const ptr = Module.allocate_binary_buffer(mergedBuffer.length);
      if (ptr) {
        Module.HEAPU8.set(mergedBuffer, ptr);
        const result = JSON.parse(wallet.ingest_sparse_transactions(ptr, mergedBuffer.length, 0, true));
        Module.free_binary_buffer(ptr);

        if (result.success) {
          totalOutputsFound += result.txs_matched || 0;
          if (result.stake_heights?.length) allStakeHeights.push(...result.stake_heights);
          if (result.audit_heights?.length) allAuditHeights.push(...result.audit_heights);
        }
      }

      completed++;

      if (onProgress) {
        onProgress({
          progress: completed / batches.length,
          scannedBlocks: Math.min(Math.floor(completed / batches.length * sortedChunks.length * 1000), sortedChunks.length * 1000),
          totalBlocks: sortedChunks.length * 1000,
          completedChunks: Math.floor(completed / batches.length * sortedChunks.length),
          totalChunks: sortedChunks.length,
          viewTagMatches: allMatches.length,
          bytesReceived: totalBytes,
          blocksPerSecond: 0
        });
      }

      await yieldIfNeeded();
    }

    return totalOutputsFound;
  }

  /**
   * Phase 3 (Fast): Fetch stake returns using sparse format
   * Much faster than fetchStakeReturnBlocks - fetches only specific heights
   */
  private async fetchStakeReturnsSparse(
    wallet: any,
    Module: any,
    stakeHeights: number[],
    networkHeight: number,
    onProgress?: (progress: ScanProgress) => void,
    progressBase: number = 0.90,
    progressRange: number = 0.07
  ): Promise<number> {
    const STAKE_RETURN_OFFSET = 21601;

    // Calculate return heights and filter out:
    // 1. Future blocks (not yet mined)
    // 2. Duplicates
    // Note: Pre-Carrot stake returns (heights < 334750) ARE now processed.
    // Previous filter was incorrectly skipping all legacy stake returns.
    const returnHeights = stakeHeights
      .map(h => h + STAKE_RETURN_OFFSET)
      .filter(h => h <= networkHeight)
      .filter((h, i, arr) => arr.indexOf(h) === i); // Dedupe

    if (returnHeights.length === 0) {
      return 0;
    }

    try {
      const startTime = Date.now();

      // Use sparse-by-heights endpoint which now correctly uses TXI index
      // to find all transactions (miner_tx, protocol_tx, user_txs) at specific heights
      const MAX_HEIGHTS_PER_REQUEST = 500;
      let txsMatched = 0;
      let txsProcessedTotal = 0;

      for (let batchStart = 0; batchStart < returnHeights.length; batchStart += MAX_HEIGHTS_PER_REQUEST) {
        const batchHeights = returnHeights.slice(batchStart, batchStart + MAX_HEIGHTS_PER_REQUEST);

        // Report smooth progress within stake returns phase
        if (onProgress && returnHeights.length > 0) {
          const stakeProgress = batchStart / returnHeights.length;
          const overallProgress = progressBase + (progressRange * stakeProgress);
          onProgress({
            progress: stakeProgress,
            phase: '3b',
            message: `Processing stake returns... ${Math.round(stakeProgress * 100)}%`,
            scannedBlocks: batchStart,
            totalBlocks: returnHeights.length,
            completedChunks: 0,
            totalChunks: 0,
            viewTagMatches: 0,
            bytesReceived: 0,
            blocksPerSecond: 0,
            overallProgress,
            percentage: Math.round(overallProgress * 100),
            transactionsFound: txsMatched,
            statusMessage: 'Processing stake returns...'
          });
        }

        await yieldToUI();

        const response = await fetch('/vault/api/wallet/sparse-by-heights', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ heights: batchHeights })
        });

        if (!response.ok) {
          const error = await response.text();
          console.error(`[CSPScanService] 🎰 Sparse heights fetch failed:`, error);
          continue; // Try next batch even if one fails
        }

        const data = new Uint8Array(await response.arrayBuffer());

        if (data.length < 4) {
          console.warn(`[CSPScanService] 🎰 Empty sparse response for batch`);
          continue;
        }

        // Process using ingest_sparse_transactions (same as Phase 2)
        if (typeof wallet.ingest_sparse_transactions !== 'function') {
          console.error(`[CSPScanService] 🎰 ingest_sparse_transactions not available`);
          return 0;
        }

        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        const chunkCount = view.getUint32(0, true);
        let offset = 4;

        let consecutiveFailures = 0;
        const MAX_CONSECUTIVE_FAILURES = 3;
        let wasmCorrupted = false;

        startFrame();
        for (let c = 0; c < chunkCount && offset + 8 <= data.length; c++) {
          if (wasmCorrupted) {
            offset += 8;
            const skipSize = view.getUint32(offset - 4, true);
            offset += skipSize;
            continue;
          }

          const chunkStartHeight = view.getUint32(offset, true);
          offset += 4;
          const dataSize = view.getUint32(offset, true);
          offset += 4;

          if (dataSize > 0 && offset + dataSize <= data.length) {
            const sparseData = data.subarray(offset, offset + dataSize);
            offset += dataSize;

            try {
              const ptr = Module.allocate_binary_buffer(sparseData.length);
              if (ptr) {
                Module.HEAPU8.set(sparseData, ptr);
                const resultJson = wallet.ingest_sparse_transactions(ptr, sparseData.length, chunkStartHeight, true);
                Module.free_binary_buffer(ptr);

                const result = JSON.parse(resultJson);
                if (result.success) {
                  txsMatched += result.txs_matched || 0;
                  txsProcessedTotal += result.txs_processed || 0;
                  consecutiveFailures = 0;
                } else {
                  console.error(`[CSPScanService] 🎰 Sparse ingest failed for chunk at height ${chunkStartHeight}:`, result.error);
                  consecutiveFailures++;
                }
              } else {
                console.error(`[CSPScanService] 🎰 Buffer allocation failed for chunk at height ${chunkStartHeight}`);
                consecutiveFailures++;
              }
            } catch (chunkError: any) {
              console.error(`[CSPScanService] 🎰 Chunk ${chunkStartHeight} error (continuing):`, chunkError?.message || chunkError);
              consecutiveFailures++;

              if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
                console.warn(`[CSPScanService] ⚠️ WASM memory likely corrupted - stopping Phase 3b`);
                wasmCorrupted = true;
              }
            }
            await yieldIfNeeded();
          } else {
            offset += dataSize;
          }
        }
      }

      return txsMatched;

    } catch (e: any) {
      console.error(`[CSPScanService] 🎰 Fetch stake returns sparse failed:`, e?.message || e);
      return 0;
    }
  }

  /**
   * Phase 3c (Fast): Fetch AUDIT returns using sparse format
   * AUDIT returns unlock at audit_height + 7201 (~1 week, 1/3 of stake period)
   */
  private async fetchAuditReturnsSparse(
    wallet: any,
    Module: any,
    auditHeights: number[],
    networkHeight: number
  ): Promise<number> {
    const AUDIT_RETURN_OFFSET = 7201;

    // Calculate return heights and filter out:
    // 1. Future blocks (not yet mined)
    // 2. Duplicates
    // Note: Pre-Carrot audit returns ARE now processed.
    // Previous filter was incorrectly skipping all legacy audit returns.
    const returnHeights = auditHeights
      .map(h => h + AUDIT_RETURN_OFFSET)
      .filter(h => h <= networkHeight)
      .filter((h, i, arr) => arr.indexOf(h) === i); // Dedupe

    if (returnHeights.length === 0) {
      return 0;
    }

    try {
      const startTime = Date.now();

      // Use sparse-by-heights endpoint which now correctly uses TXI index
      // to find all transactions (miner_tx, protocol_tx, user_txs) at specific heights
      const MAX_HEIGHTS_PER_REQUEST = 500;
      let txsMatched = 0;
      let txsProcessedTotal = 0;

      for (let batchStart = 0; batchStart < returnHeights.length; batchStart += MAX_HEIGHTS_PER_REQUEST) {
        const batchHeights = returnHeights.slice(batchStart, batchStart + MAX_HEIGHTS_PER_REQUEST);
        // v5.51.0: Yield to UI before each batch
        await yieldToUI();

        const response = await fetch('/vault/api/wallet/sparse-by-heights', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ heights: batchHeights })
        });

        if (!response.ok) {
          const error = await response.text();
          console.error(`[CSPScanService] 🔍 Sparse heights fetch failed:`, error);
          continue; // Try next batch even if one fails
        }

        const data = new Uint8Array(await response.arrayBuffer());

        if (data.length < 4) {
          console.warn(`[CSPScanService] 🔍 Empty sparse response for batch`);
          continue;
        }

        // Process using ingest_sparse_transactions (same as Phase 2)
        if (typeof wallet.ingest_sparse_transactions !== 'function') {
          console.error(`[CSPScanService] 🔍 ingest_sparse_transactions not available`);
          return 0;
        }

        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        const chunkCount = view.getUint32(0, true);
        let offset = 4;

        let consecutiveFailures = 0;
        const MAX_CONSECUTIVE_FAILURES = 3;
        let wasmCorrupted = false;

        startFrame();
        for (let c = 0; c < chunkCount && offset + 8 <= data.length; c++) {
          if (wasmCorrupted) {
            offset += 8;
            const skipSize = view.getUint32(offset - 4, true);
            offset += skipSize;
            continue;
          }

          const chunkStartHeight = view.getUint32(offset, true);
          offset += 4;
          const dataSize = view.getUint32(offset, true);
          offset += 4;

          if (dataSize > 0 && offset + dataSize <= data.length) {
            const sparseData = data.subarray(offset, offset + dataSize);
            offset += dataSize;

            try {
              const ptr = Module.allocate_binary_buffer(sparseData.length);
              if (ptr) {
                Module.HEAPU8.set(sparseData, ptr);
                const resultJson = wallet.ingest_sparse_transactions(ptr, sparseData.length, chunkStartHeight, true);
                Module.free_binary_buffer(ptr);

                const result = JSON.parse(resultJson);
                if (result.success) {
                  txsMatched += result.txs_matched || 0;
                  txsProcessedTotal += result.txs_processed || 0;
                  consecutiveFailures = 0;
                } else {
                  console.error(`[CSPScanService] 🔍 Audit sparse ingest failed for chunk at height ${chunkStartHeight}:`, result.error);
                  consecutiveFailures++;
                }
              } else {
                console.error(`[CSPScanService] 🔍 Buffer allocation failed for chunk at height ${chunkStartHeight}`);
                consecutiveFailures++;
              }
            } catch (chunkError: any) {
              console.error(`[CSPScanService] 🔍 Audit chunk ${chunkStartHeight} error (continuing):`, chunkError?.message || chunkError);
              consecutiveFailures++;

              if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
                console.warn(`[CSPScanService] ⚠️ WASM memory likely corrupted - stopping Phase 3c`);
                wasmCorrupted = true;
              }
            }
            await yieldIfNeeded();
          } else {
            offset += dataSize;
          }
        }
      }

      return txsMatched;

    } catch (e: any) {
      console.error(`[CSPScanService] 🔍 Fetch audit returns sparse failed:`, e?.message || e);
      return 0;
    }
  }
}

// Export simple singleton - no lazy wrapper needed since we use dynamic import for WalletService
export const cspScanService = CSPScanService.getInstance();
