import React, { useEffect, useState, useMemo } from 'react';
import { RefreshCw, Download, Shield } from './Icons';
import { useWallet } from '../services/WalletContext';

interface LoadingScreenProps {
  onComplete: () => void;
}

const LoadingScreen: React.FC<LoadingScreenProps> = ({ onComplete }) => {
  const wallet = useWallet();
  const [hasTriggeredComplete, setHasTriggeredComplete] = useState(false);

  // Track if we've actually requested a start to the scan
  // This prevents the screen from dismissing immediately if the restored wallet state says 100%
  const [scanInitiated, setScanInitiated] = useState(false);

  // Track the maximum progress seen to prevent jumping backward
  const [maxProgress, setMaxProgress] = useState(0);

  // Get real progress from wallet context
  const progress = wallet.scanProgress;
  const isScanning = wallet.isScanning;

  // Calculate smooth progress based on block heights (not phase-based percentages)
  // This gives a consistent 0-100% progression without jumping around
  const { walletHeight, daemonHeight, scanStartHeight } = wallet.syncStatus;

  const rawPercentage = useMemo(() => {
    // If we have scanStartHeight and daemonHeight, calculate progress based on blocks
    if (scanStartHeight !== undefined && daemonHeight > 0 && daemonHeight > scanStartHeight) {
      const totalBlocks = daemonHeight - scanStartHeight;
      const scannedBlocks = Math.max(0, walletHeight - scanStartHeight);
      return Math.min(100, Math.max(0, (scannedBlocks / totalBlocks) * 100));
    }
    // Fallback to the reported progress if heights aren't available
    return wallet.syncStatus.progress > 0
      ? wallet.syncStatus.progress
      : (progress?.percentage ?? (progress?.overallProgress ? progress.overallProgress * 100 : 0));
  }, [walletHeight, daemonHeight, scanStartHeight, wallet.syncStatus.progress, progress]);

  // Only allow progress to increase, never decrease (prevents jumping backward)
  // Reset maxProgress when scan is initiated fresh
  useEffect(() => {
    if (scanInitiated && rawPercentage > maxProgress) {
      setMaxProgress(rawPercentage);
    }
  }, [rawPercentage, scanInitiated, maxProgress]);

  // Reset max progress when starting a new scan
  useEffect(() => {
    if (!scanInitiated) {
      setMaxProgress(0);
    }
  }, [scanInitiated]);

  const percentage = scanInitiated ? Math.max(maxProgress, rawPercentage) : 0;

  const statusMessage = progress?.statusMessage ?? 'Syncing wallet...';
  const transactionsFound = progress?.transactionsFound ?? 0;
  
  // DEBUG: Show wallet state
  const wasmStatus = wallet.getWasmStatus();
  const walletState = `Ready:${wallet.isWalletReady}, Locked:${wallet.isLocked}, Init:${wallet.isInitialized}`;
  const wasmState = `WASM.isReady:${wasmStatus.isReady}, WASM.hasWallet:${wasmStatus.hasWallet}`;
  const errorState = `ResErr:${!!wallet.restorationError}, InitErr:${!!wallet.initError}`;
  const errorMsgs = `ResErrMsg:"${wallet.restorationError || 'null'}", InitErrMsg:"${wallet.initError || 'null'}"`;
  const debugInfo = `Scanning:${isScanning}, Progress:${percentage.toFixed(1)}%, Raw:${progress?.percentage ?? 'null'}`;

  // Start scan when component mounts if not already scanning
  useEffect(() => {
    let attempts = 0;
    const maxAttempts = 20; // Try for 10 seconds

    const attemptScan = () => {
      attempts++;
      if (isScanning) {
        if (!scanInitiated) setScanInitiated(true);
        return true; // Success, stop retrying
      }

      if (wallet.isWalletReady) {
        wallet.startScan();
        setScanInitiated(true);
      }

      return false; // Keep retrying
    };

    // Try immediately
    if (attemptScan()) return;

    // Keep retrying every 500ms
    const interval = setInterval(() => {
      if (attemptScan() || attempts >= maxAttempts) {
        clearInterval(interval);
      }
    }, 500);

    return () => clearInterval(interval);
  }, [isScanning, wallet.isWalletReady]); // Re-run if isScanning changes

  // Check for completion
  useEffect(() => {
    // CRITICAL FIX: Only consider complete if we have actually initiated a scan
    // This handles the "Zombie Restore" case where we start with 100% progress but need to rescan
    const isComplete = scanInitiated && !isScanning && percentage >= 99.9;

    if (!hasTriggeredComplete && isComplete && wallet.isWalletReady) {
      setHasTriggeredComplete(true);
      setTimeout(onComplete, 800);
    }
  }, [isScanning, percentage, hasTriggeredComplete, onComplete, wallet.isWalletReady, scanInitiated]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#0b0b15] font-sans animate-fade-in" style={{}}>

      {/* Background Ambience */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-accent-primary/5 blur-[120px] rounded-full pointer-events-none"></div>

      {/* ERROR STATE: WASM wallet not available */}
      {wallet.isWalletReady && !wasmStatus.hasWallet && (
        <div className="relative z-10 flex flex-col items-center w-full max-w-lg px-6">
          <div className="w-16 h-16 rounded-full bg-red-500/20 flex items-center justify-center mb-6">
            <span className="text-red-500 text-3xl">!</span>
          </div>
          <h2 className="text-2xl font-bold text-white mb-3">Wallet Restoration Failed</h2>
          <p className="text-text-secondary text-center mb-4">
            WASM wallet is not available after unlock. This may be a mobile browser issue.
          </p>
          {(wallet.initError || wallet.restorationError) && (
            <div className="bg-orange-500/10 border border-orange-500/30 rounded-lg p-4 mb-4 w-full">
              <p className="text-orange-400 text-sm font-mono break-words">
                {wallet.restorationError || wallet.initError}
              </p>
            </div>
          )}
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 mb-4 text-left w-full">
            <p className="text-xs text-red-400 font-mono mb-2">{walletState}</p>
            <p className="text-xs text-red-400 font-mono mb-2">{wasmState}</p>
            <p className="text-xs text-purple-400 font-mono mb-2">{errorState}</p>
            <p className="text-xs text-orange-300 font-mono mb-2 break-all">{errorMsgs}</p>
          </div>
          {/* DEBUG LOG - visible on error screen */}
          <div className="bg-gray-800/50 border border-gray-600/30 rounded-lg p-3 mb-4 text-left w-full max-h-64 overflow-y-auto">
            <p className="text-xs text-gray-400 font-mono mb-2">Init Log:</p>
            {wallet.initLog.map((log, i) => <p key={i} className="text-xs text-green-400 font-mono mb-1 whitespace-pre-wrap break-words">{log}</p>)}
            {wallet.initLog.length === 0 && <p className="text-xs text-gray-500 font-mono">No logs captured yet...</p>}
          </div>
          <div className="flex gap-3 w-full">
            <button
              onClick={() => {
                // Clear sessionStorage to force fresh init
                sessionStorage.clear();
                window.location.reload();
              }}
              className="flex-1 px-4 py-3 bg-yellow-600 rounded-lg text-white font-medium text-sm"
            >
              Clear Session & Reload
            </button>
            <button
              onClick={() => window.location.reload()}
              className="flex-1 px-4 py-3 bg-accent-primary rounded-lg text-white font-medium text-sm"
            >
              Reload Page
            </button>
          </div>
        </div>
      )}

      {/* NORMAL LOADING STATE */}
      {(!wallet.isWalletReady || wasmStatus.hasWallet) && (
        <div className="relative z-10 flex flex-col items-center w-full max-w-lg mb-10">

          {/* Spinner */}
          <div className="relative mb-10">
            {/* Outer Ring Track */}
            <div className="w-20 h-20 rounded-full border-[3px] border-white/5"></div>

            {/* Spinner Segment (Animated) */}
            <div className="absolute inset-0 w-20 h-20 rounded-full border-[3px] border-accent-primary border-t-transparent border-l-transparent border-r-transparent animate-spin shadow-[0_0_20px_rgba(99,102,241,0.4)]"></div>

            {/* Inner Icon */}
            <div className="absolute inset-0 flex items-center justify-center">
              <RefreshCw size={24} className="text-accent-primary" />
            </div>
          </div>

          {/* Typography - Simplified */}
          <h2 className="text-3xl font-bold text-white mb-3 tracking-tight">Syncing Wallet</h2>
          <p className="text-text-secondary font-medium text-base mb-2">{statusMessage}</p>
          {transactionsFound > 0 && (
            <p className="text-accent-primary text-sm mb-10 font-mono">
              Found {transactionsFound.toLocaleString()} transactions
            </p>
          )}
          {transactionsFound === 0 && (
            <p className="text-text-muted text-sm mb-10">This will take several minutes</p>
          )}

          {/* Progress Bar Section - Unified */}
          <div className="w-full">
            <div className="h-3 w-full bg-[#1a1a2e] rounded-full overflow-hidden mb-4 border border-white/5 relative">
              <div
                className="h-full bg-accent-primary rounded-full shadow-[0_0_20px_rgba(99,102,241,0.6)] transition-all duration-500 ease-out relative overflow-hidden"
                style={{ width: `${Math.min(100, percentage)}%` }}
              >
                {/* Subtle Shimmer Overlay */}
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent translate-x-[-100%] animate-[shimmer_2s_infinite]"></div>
              </div>
            </div>

            {/* Single percentage display - no confusing block numbers */}
            <div className="flex justify-center items-center">
              <span className="text-accent-primary font-bold text-2xl font-mono">{Math.round(percentage)}%</span>
            </div>
          </div>

      </div>
      )}

      {/* Backup Reminder Banner - Fixed at Bottom */}
      <div className="absolute bottom-8 left-0 w-full flex justify-center z-10 px-4">
        <div className="rounded-xl border border-accent-primary/20 bg-accent-primary/5 backdrop-blur-sm py-3 px-5 flex items-center justify-center gap-2 w-full max-w-2xl">
          <Shield size={20} className="text-accent-primary flex-shrink-0" />
          <p className="text-white text-sm leading-relaxed text-center">
            Reminder that this is a web app and cache can be wiped. To avoid needing a full rescan, export an encrypted vault backup file from Settings. Your address book and other settings will also be saved.
          </p>
        </div>
      </div>
    </div>
  );
};

export default LoadingScreen;