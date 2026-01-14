import React, { useState, useEffect } from 'react';
import { isMobile, isIOS, isIPad13, isTablet } from 'react-device-detect';
import { Download, Share, PlusSquare } from 'lucide-react';
import { Button } from './UIComponents';

// Helper to detect if the app is running in "Standalone" (Installed) mode
const useIsPWA = () => {
    const [isPWA, setIsPWA] = useState(false);

    useEffect(() => {
        // Standard check
        const mediaQuery = window.matchMedia('(display-mode: standalone)');
        // iOS Safari check
        const isIOSStandalone = (window.navigator as any).standalone === true;

        setIsPWA(mediaQuery.matches || isIOSStandalone);

        const handleChange = (e: MediaQueryListEvent) => {
            setIsPWA(e.matches || (window.navigator as any).standalone === true);
        };

        mediaQuery.addEventListener('change', handleChange);
        return () => mediaQuery.removeEventListener('change', handleChange);
    }, []);

    return isPWA;
};

const PWAOnlyGate: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const isPWA = useIsPWA();
    const [deferredPrompt, setDeferredPrompt] = useState<any>(null);

    useEffect(() => {
        const handleBeforeInstallPrompt = (e: any) => {
            e.preventDefault();
            setDeferredPrompt(e);
        };

        window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
        return () => window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
    }, []);

    const handleInstallClick = async () => {
        if (deferredPrompt) {
            deferredPrompt.prompt();
            const { outcome } = await deferredPrompt.userChoice;
            if (outcome === 'accepted') {
                setDeferredPrompt(null);
            }
        }
    };

    // Check if device is mobile OR tablet (including iPad13+)
    const isMobileOrTablet = isMobile || isTablet || isIPad13;

    // 1. If it's Desktop (not mobile/tablet), always render the app.
    // 2. If it's Mobile/Tablet AND it is already installed (isPWA), render the app.
    if (!isMobileOrTablet || isPWA) {
        return <>{children}</>;
    }

    // ------------------------------------------------------
    // Mobile AND NOT Installed -> Show Blocker
    // ------------------------------------------------------
    return (
        <div className="fixed inset-0 bg-[#0b0b15] flex flex-col items-center justify-center p-6 text-center z-[100]">
            {/* Background Effects */}
            <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-indigo-900/20 via-[#0b0b15] to-[#0b0b15] pointer-events-none"></div>

            <div className="relative z-10 flex flex-col items-center max-w-md w-full animate-fade-in">
                <img
                    src="/vault/assets/img/salvium.png"
                    alt="Salvium Vault"
                    className="w-20 h-20 mb-6 drop-shadow-[0_0_15px_rgba(99,102,241,0.5)]"
                />

                <h1 className="text-2xl font-bold text-white mb-3">Install App Required</h1>
                <p className="text-text-secondary mb-8 leading-relaxed">
                    For the best security and performance, Salvium Vault must be installed to your home screen.
                </p>

                <div className="bg-[#13131f] border border-white/10 rounded-xl p-6 w-full shadow-xl">
                    {isIOS ? (
                        <div className="flex flex-col gap-4 text-left">
                            <div className="flex items-center gap-3 text-text-muted text-sm">
                                <div className="w-8 h-8 rounded-full bg-white/5 flex items-center justify-center shrink-0">
                                    <span className="font-bold text-white">1</span>
                                </div>
                                <span>Tap the <strong className="text-white">Share</strong> icon below</span>
                                <Share size={18} className="text-accent-primary ml-auto" />
                            </div>

                            <div className="w-px h-4 bg-white/5 ml-4"></div>

                            <div className="flex items-center gap-3 text-text-muted text-sm">
                                <div className="w-8 h-8 rounded-full bg-white/5 flex items-center justify-center shrink-0">
                                    <span className="font-bold text-white">2</span>
                                </div>
                                <span>Select <strong className="text-white">Add to Home Screen</strong></span>
                                <PlusSquare size={18} className="text-accent-primary ml-auto" />
                            </div>
                        </div>
                    ) : (
                        <div className="flex flex-col gap-4">
                            <p className="text-sm text-text-muted mb-2">Install the app to access your wallet</p>
                            <Button
                                variant="primary"
                                onClick={handleInstallClick}
                                className="w-full flex items-center justify-center gap-2 py-3"
                            >
                                <Download size={18} />
                                Install App
                            </Button>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default PWAOnlyGate;
