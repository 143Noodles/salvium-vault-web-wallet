import React from 'react';
import { ExternalLink, X } from './Icons';
import { Overlay } from './UIComponents';
import { isMobile, isTablet, isIPad13 } from 'react-device-detect';

// Device detection helpers for responsive layouts
const isTabletDevice = isTablet || isIPad13;
const isMobileOrTablet = isMobile || isTabletDevice; // Tablets use mobile layouts

interface TransactionOverlayProps {
    isOpen: boolean;
    onClose: () => void;
    txId: string | null;
}

const TransactionOverlay: React.FC<TransactionOverlayProps> = ({ isOpen, onClose, txId }) => {
    if (!isOpen || !txId) return null;

    const Content = () => (
        <div className="flex flex-col h-full bg-[#151525]">
            {/* Header for Inline/Desktop Mode */}
            {!isMobileOrTablet && (
                <div className="flex items-center justify-between p-4 border-b border-white/5 bg-white/5 shrink-0">
                    <h3 className="font-bold text-lg text-white">Transaction Details</h3>
                    <button onClick={onClose} className="text-text-muted hover:text-white transition-colors">
                        <X size={20} />
                    </button>
                </div>
            )}

            <div className="flex-1 overflow-y-auto p-4 flex flex-col min-h-0">
                {/* Custom Sub-header */}
                <div className="flex items-center gap-3 mb-4 p-2 bg-white/5 rounded-xl border border-white/10 shrink-0">
                    <div className="p-2 bg-accent-primary/10 rounded-lg text-accent-primary">
                        <ExternalLink size={20} />
                    </div>
                    <div className="min-w-0 flex-1">
                        <p className="text-xs text-text-muted uppercase tracking-wider">Transaction Hash</p>
                        <p className="text-sm font-mono text-white truncate text-ellipsis">{txId}</p>
                    </div>
                </div>

                {/* Content - Iframe */}
                <div className="flex-1 bg-white rounded-xl overflow-hidden border border-white/10 relative min-h-0">
                    <iframe
                        src={`https://salvium.tools/transaction?hash=${txId}`}
                        className="absolute inset-0 w-full h-full border-none"
                        title="Salvium Explorer Transaction"
                    />
                </div>

                {/* Footer info */}
                <div className="pt-4 text-center shrink-0">
                    <p className="text-xs text-text-muted">
                        Powered by salvium.tools explorer
                    </p>
                </div>
            </div>
        </div>
    );

    // Desktop: Inline Absolute Overlay
    if (!isMobileOrTablet) {
        return (
            <div className="absolute inset-0 z-50 bg-[#151525] flex flex-col animate-fade-in rounded-2xl overflow-hidden">
                <Content />
            </div>
        );
    }

    // Mobile/Tablet: Standard Overlay
    return (
        <Overlay
            isOpen={isOpen}
            onClose={onClose}
            title="Transaction Details"
            className="max-w-5xl h-[85vh]"
        >
            <Content />
        </Overlay>
    );
};

export default TransactionOverlay;


