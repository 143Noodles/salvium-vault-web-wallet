import React, { useState, useEffect, useRef, useCallback } from 'react';
import { WalletProvider, useWallet, WalletStats } from './services/WalletContext';
import Dashboard from './components/Dashboard';
import Onboarding from './components/Onboarding';
import LoadingScreen from './components/LoadingScreen';
import LockScreen from './components/LockScreen';
import RecoveryOptionsScreen from './components/RecoveryOptionsScreen';
import SendPage from './components/SendPage';
import ReceivePage from './components/ReceivePage';
import StakingPage from './components/StakingPage';
import HistoryPage from './components/HistoryPage';
import SettingsPage from './components/SettingsPage';
import {
  LayoutDashboard,
  TrendingUp,
  Settings,
  Menu,
  X,
  Lock,
  Send,
  Download,
  History,
  Cpu,
  Monitor,
  Database,
  Activity,
  Network
} from './components/Icons';

import { MobileNavBar } from './components/MobileNavBar';
import { MobileHeader } from './components/MobileHeader';

import { isMobileOrTablet, isDesktop } from './utils/device';
import { isBrowser } from 'react-device-detect';
import { useMobileScaling } from './hooks/useMobileScaling';

const isDesktopOnly = isDesktop;

export enum TabView {
  DASHBOARD = 'DASHBOARD',
  SEND = 'SEND',
  RECEIVE = 'RECEIVE',
  HISTORY = 'HISTORY',
  STAKING = 'STAKING',
  SETTINGS = 'SETTINGS'
}

const APP_VERSION = '4.0.0-new-ui';

type AppState = 'initializing' | 'setup' | 'loading' | 'dashboard' | 'locked';

const AppContent: React.FC = () => {
  const wallet = useWallet();
  useMobileScaling();

  const [appState, setAppState] = useState<AppState>('initializing');
  const [activeTab, setActiveTab] = useState<TabView>(TabView.DASHBOARD);
  const previousTabRef = useRef<TabView>(TabView.DASHBOARD);

  const [navParams, setNavParams] = useState<any>(null);

  const handleNavigate = (tab: TabView, params?: any) => {
    if (params) {
      setNavParams(params);
    } else {
      setNavParams(null);
    }

    if (tab === TabView.SETTINGS && activeTab === TabView.SETTINGS) {
      setActiveTab(previousTabRef.current);
      return;
    }

    if (tab === TabView.SETTINGS) {
      previousTabRef.current = activeTab;
    }

    setActiveTab(tab);
  };

  const [needsScan, setNeedsScan] = useState(false);
  const [autoLockEnabled, setAutoLockEnabled] = useState(true);
  const [autoLockMinutes, setAutoLockMinutes] = useState(15);
  const lastActivityRef = useRef(Date.now());

  useEffect(() => {
    const init = async () => {
      try {
        const storedAutoLock = localStorage.getItem('salvium_autolock_enabled');
        const storedMinutes = localStorage.getItem('salvium_autolock_minutes');

        if (storedAutoLock !== null) {
          setAutoLockEnabled(storedAutoLock === 'true');
        }
        if (storedMinutes !== null) {
          setAutoLockMinutes(parseInt(storedMinutes));
        }
      } catch (e) {
        console.warn('Failed to load settings:', e);
      }

      if (!wallet.isInitialized) return;

      const hasWallet = localStorage.getItem('salvium_wallet_created');
      if (!hasWallet) {
        setAppState('setup');
        return;
      }

      if (wallet.isLocked) {
        setAppState('locked');
        return;
      }

      if (!wallet.isWalletReady) {
        setAppState('initializing');
        return;
      }

      const initialScanComplete = localStorage.getItem('salvium_initial_scan_complete');
      if (initialScanComplete === 'false') {
        setNeedsScan(true);
        setAppState('loading');
        return;
      }

      setAppState('dashboard');
    };

    if (wallet.isInitialized) {
      init();
    }
  }, [wallet.isInitialized, wallet.isLocked, wallet.isWalletReady]);

  const isSynced = !wallet.syncStatus.isSyncing &&
    wallet.syncStatus.walletHeight >= wallet.syncStatus.daemonHeight &&
    wallet.syncStatus.daemonHeight > 0;
  const isConnected = wallet.syncStatus.daemonHeight > 0;

  const lockWallet = useCallback(() => {
    wallet.lockWallet();
    setAppState('locked');
  }, [wallet]);

  const updateActivity = () => {
    lastActivityRef.current = Date.now();
  };

  useEffect(() => {
    const events = ['mousedown', 'keydown', 'touchstart', 'scroll', 'mousemove'];
    const handleActivity = () => updateActivity();
    events.forEach(event => window.addEventListener(event, handleActivity));

    const interval = setInterval(() => {
      if (appState === 'dashboard' && autoLockEnabled) {
        const now = Date.now();
        const elapsedMinutes = (now - lastActivityRef.current) / 1000 / 60;

        if (elapsedMinutes >= autoLockMinutes) {
          lockWallet();
        }
      }
    }, 10000);

    return () => {
      clearInterval(interval);
      events.forEach(event => window.removeEventListener(event, handleActivity));
    };
  }, [appState, autoLockEnabled, autoLockMinutes, lockWallet]);

  useEffect(() => {
    const requestPersistence = async () => {
      if (navigator.storage && navigator.storage.persist) {
        await navigator.storage.persist();
      }
    };
    requestPersistence();
  }, []);

  useEffect(() => {
    let wakeLock: any = null;

    const requestWakeLock = async () => {
      if (appState === 'locked') return;
      if (wakeLock !== null && !wakeLock.released) return;
      try {
        if ('wakeLock' in navigator) {
          wakeLock = await (navigator as any).wakeLock.request('screen');
        }
      } catch (err) { /* ignore */ }
    };

    const handleVisibilityChange = async () => {
      if (document.visibilityState === 'visible') {
        await requestWakeLock();
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    document.addEventListener('click', requestWakeLock);

    requestWakeLock();

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      document.removeEventListener('click', requestWakeLock);
      if (wakeLock) {
        wakeLock.release().catch(() => { });
      }
    };
  }, [appState]);

  const handleOnboardingComplete = (mode: 'create' | 'restore') => {
    updateActivity();
    if (mode === 'restore') {
      localStorage.setItem('salvium_initial_scan_complete', 'false');
      setNeedsScan(true);
      setAppState('loading');
    } else {
      localStorage.setItem('salvium_initial_scan_complete', 'true');
      setAppState('dashboard');
    }
  };

  const handleLoadingComplete = () => {
    updateActivity();
    setNeedsScan(false);
    localStorage.setItem('salvium_initial_scan_complete', 'true');
    setAppState('dashboard');
  };

  const handleUnlock = () => {
    updateActivity();
    setAppState('dashboard');
  };

  const handleReset = async () => {
    await wallet.resetWallet();
    setAppState('setup');
    updateActivity();
  };

  const handleAutoLockSettingsChange = (enabled: boolean, minutes: number) => {
    setAutoLockEnabled(enabled);
    setAutoLockMinutes(minutes);
    localStorage.setItem('salvium_settings', JSON.stringify({ autoLockEnabled: enabled, autoLockMinutes: minutes }));
    localStorage.setItem('salvium_autolock_enabled', String(enabled));
    localStorage.setItem('salvium_autolock_minutes', String(minutes));
    updateActivity();
  };

  // --- Render ---

  if (appState === 'initializing') {
    return (
      <div className="fixed inset-0 z-50 bg-bg-primary flex items-center justify-center h-[100dvh]">
        <div className="flex flex-col items-center gap-4 p-6 max-w-sm text-center">
          {wallet.initError ? (
            <>
              <div className="w-12 h-12 rounded-full bg-red-500/20 flex items-center justify-center">
                <span className="text-red-500 text-2xl">!</span>
              </div>
              <p className="text-red-400 font-medium">Failed to Initialize</p>
              <p className="text-text-muted text-sm">{wallet.initError}</p>
              <p className="text-text-muted text-xs mt-2">
                This may occur on some mobile browsers due to WASM limitations.
                Try using a desktop browser or Chrome on Android.
              </p>
              <button
                onClick={() => window.location.reload()}
                className="mt-4 px-4 py-2 bg-accent-primary rounded-lg text-white text-sm"
              >
                Retry
              </button>
            </>
          ) : (
            <>
              <div className="w-12 h-12 border-4 border-accent-primary border-t-transparent rounded-full animate-spin"></div>
              <p className="text-text-muted text-sm">Initializing wallet...</p>
            </>
          )}
        </div>
      </div>
    );
  }

  if (appState === 'setup') {
    return <Onboarding onComplete={handleOnboardingComplete} />;
  }

  if (appState === 'loading') {
    return <LoadingScreen onComplete={handleLoadingComplete} />;
  }

  if (wallet.needsRecovery) {
    return (
      <RecoveryOptionsScreen
        walletAddress={wallet.address}
        onRestoreFromBackup={async () => {
          await wallet.handleBackupRestored();
          setAppState('dashboard');
        }}
        onStartFullRescan={() => {
          wallet.proceedWithFullRescan();
          localStorage.setItem('salvium_initial_scan_complete', 'false');
          setNeedsScan(true);
          setAppState('loading');
        }}
      />
    );
  }

  if (appState === 'locked') {
    return <LockScreen onUnlock={handleUnlock} onReset={handleReset} />;
  }

  if (!appState || appState === 'initializing') {
    const initialScanComplete = localStorage.getItem('salvium_initial_scan_complete');
    return (
      <div className="min-h-screen bg-bg-primary text-text-primary p-8">
        <div className="max-w-2xl mx-auto">
          <h1 className="text-2xl font-bold mb-4">🐛 Debug: App State</h1>
          <div className="bg-bg-secondary p-4 rounded-lg space-y-2 font-mono text-sm">
            <div>appState: <span className="text-accent-primary">{appState || 'null'}</span></div>
            <div>isInitialized: <span className="text-accent-primary">{String(wallet.isInitialized)}</span></div>
            <div>isLocked: <span className="text-accent-primary">{String(wallet.isLocked)}</span></div>
            <div>isWalletReady: <span className="text-accent-primary">{String(wallet.isWalletReady)}</span></div>
            <div>needsRecovery: <span className="text-accent-primary">{String(wallet.needsRecovery)}</span></div>
            <div>hasWallet (localStorage): <span className="text-accent-primary">{String(!!localStorage.getItem('salvium_wallet_created'))}</span></div>
            <div>initialScanComplete: <span className="text-accent-primary">{initialScanComplete || 'null'}</span></div>
          </div>
          <div className="mt-4 bg-bg-secondary p-4 rounded-lg">
            <h2 className="font-bold mb-2">Init Log:</h2>
            <div className="space-y-1 font-mono text-xs">
              {wallet.initLog?.map((log, i) => (
                <div key={i}>{log}</div>
              )) || <div>No logs</div>}
            </div>
          </div>
          <button
            onClick={() => {
              sessionStorage.clear();
              window.location.reload();
            }}
            className="mt-4 px-4 py-2 bg-accent-primary text-white rounded-lg"
          >
            Clear Session & Reload
          </button>
        </div>
      </div>
    );
  }

  const NavItem = ({ tab, icon: Icon, label }: { tab: TabView; icon: any; label: string }) => {
    const isActive = activeTab === tab;
    return (
      <button
        onClick={() => {
          setActiveTab(tab);
        }}
        className={`flex items-center justify-start gap-3 px-4 py-4 my-2 mx-4 rounded-xl transition-all duration-200 w-auto text-lg font-medium
          ${isActive
            ? 'bg-accent-primary text-white shadow-lg shadow-accent-primary/20'
            : 'text-text-secondary hover:text-white hover:bg-white/5'
          }`}
      >
        <Icon size={24} className={isActive ? 'text-white' : 'text-text-muted'} />
        {label}
      </button>
    );
  };

  return (
    <>
      <div className="h-[100dvh] bg-bg-primary text-text-primary flex relative overflow-hidden">

        {isMobileOrTablet && (
          <MobileHeader activeTab={activeTab} onNavigate={handleNavigate} onLock={lockWallet} />
        )}

        {isDesktopOnly && (
          <aside className="flex flex-col w-72 fixed h-full z-20 border-r border-border-color bg-[#0f0f1a]">

            <nav className="py-4 flex flex-col justify-start pt-8 space-y-1">
              <NavItem tab={TabView.DASHBOARD} icon={LayoutDashboard} label="Dashboard" />
              <NavItem tab={TabView.SEND} icon={Send} label="Send" />
              <NavItem tab={TabView.RECEIVE} icon={Download} label="Receive" />
              <NavItem tab={TabView.STAKING} icon={TrendingUp} label="Staking" />
              <NavItem tab={TabView.HISTORY} icon={History} label="History" />
              <NavItem tab={TabView.SETTINGS} icon={Settings} label="Settings" />
            </nav>

            <div className="mt-auto p-6 pb-20 space-y-4">
              <button
                onClick={lockWallet}
                className="flex items-center justify-center gap-2 text-sm font-medium text-text-muted hover:text-white transition-colors w-full px-2"
              >
                <Lock size={16} />
                <span>Lock Wallet</span>
              </button>

              <div className="bg-[#151525] p-4 rounded-xl border border-white/5 shadow-inner-light">
                <div className="flex items-center gap-2.5 mb-2">
                  <Cpu size={16} className="text-text-muted" />
                  <span className="text-sm font-medium text-text-secondary">Network Status</span>
                </div>

                <div className="flex items-center justify-between mb-3">
                  <span className="text-base font-bold text-white tracking-tight">
                    {!isConnected ? 'Error' : isSynced ? 'Synced' : 'Syncing'}
                  </span>

                  <div className={`relative flex items-center justify-center w-6 h-6 rounded-full bg-white/5 border border-white/5 ${isSynced ? 'shadow-[0_0_10px_rgba(16,185,129,0.2)]' : ''}`}>
                    <div className={`w-2.5 h-2.5 rounded-full ${!isConnected ? 'bg-red-500' : isSynced ? 'bg-accent-success' : 'bg-accent-warning'} ${isSynced ? 'animate-pulse' : ''}`}></div>
                  </div>
                </div>

                <div className="text-xs font-mono text-text-muted">
                  Height: <span className="text-text-secondary font-bold">{wallet.syncStatus.walletHeight.toLocaleString()}</span> / {wallet.syncStatus.daemonHeight.toLocaleString()}
                </div>
              </div>
            </div>
          </aside>
        )}

        <main className={`flex-1 ${isDesktopOnly ? 'ml-72' : ''} min-w-0 relative z-10 w-full flex flex-col`}>
          <div
            className={`
              w-full 
              px-4 md:px-8 
              max-w-[1600px] mx-auto 
              overflow-y-auto custom-scrollbar
              ${isMobileOrTablet
                ? 'pt-[calc(88px+env(safe-area-inset-top))] pb-[calc(76px+env(safe-area-inset-bottom))] h-full'
                : 'pt-6 pb-6 flex-1'
              }
            `}
          >
            {activeTab === TabView.DASHBOARD && (
              <div className="animate-fade-in h-full flex flex-col">
                <Dashboard stats={wallet.stats} onNavigate={handleNavigate} />
              </div>
            )}

            {activeTab === TabView.SEND && (
              <SendPage initialParams={navParams} />
            )}

            {activeTab === TabView.RECEIVE && (
              <ReceivePage />
            )}

            {activeTab === TabView.HISTORY && (
              <HistoryPage />
            )}

            {activeTab === TabView.STAKING && (
              <StakingPage />
            )}

            {activeTab === TabView.SETTINGS && (
              <SettingsPage
                autoLockEnabled={autoLockEnabled}
                autoLockMinutes={autoLockMinutes}
                onAutoLockChange={handleAutoLockSettingsChange}
                onRescan={() => {
                  setNeedsScan(true);
                  setAppState('loading');
                }}
                onNavigate={handleNavigate}
              />
            )}
          </div>
        </main>

        {isMobileOrTablet && (
          <MobileNavBar activeTab={activeTab} onNavigate={handleNavigate} />
        )}
      </div>
    </>
  );
};

const App: React.FC = () => {
  return (
    <WalletProvider>
      <AppContent />
    </WalletProvider>
  );
};

export default App;