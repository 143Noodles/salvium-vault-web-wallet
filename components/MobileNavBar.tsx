import React from 'react';
import { TabView } from '../App';
import { LayoutDashboard, Send, Download, TrendingUp, History } from './Icons';
import { isDesktop } from '../utils/device';

// Device detection helpers
const isDesktopOnly = isDesktop;

interface MobileNavBarProps {
    activeTab: TabView;
    onNavigate: (tab: TabView) => void;
}

export const MobileNavBar: React.FC<MobileNavBarProps> = ({ activeTab, onNavigate }) => {
    // Show on mobile and tablet, hide only on desktop
    if (isDesktopOnly) return null;
    const NavItem = ({ tab, icon: Icon, label }: { tab: TabView; icon: any; label: string }) => {
        const isActive = activeTab === tab;
        return (
            <button
                onClick={() => onNavigate(tab)}
                className={`flex flex-col items-center justify-center w-full h-full space-y-1 transition-all duration-200 active:scale-90`}
            >
                <div className={`p-1.5 rounded-xl transition-all duration-300 ${isActive ? 'bg-accent-primary/20 text-accent-primary scale-110' : 'text-text-muted'}`}>
                    <Icon size={22} strokeWidth={isActive ? 2.5 : 2} />
                </div>
                <span className={`text-[10px] font-medium transition-colors ${isActive ? 'text-white' : 'text-text-muted'}`}>
                    {label}
                </span>
            </button>
        );
    };

    return (
        <div
            className="fixed bottom-0 left-0 right-0 bg-[#0b0b15]/90 backdrop-blur-xl border-t border-white/5 z-50 lg:hidden"
            style={{
                paddingBottom: 'env(safe-area-inset-bottom)',
                height: 'calc(56px + env(safe-area-inset-bottom))'
            }}
        >
            <div className="flex justify-around items-center h-[56px] max-w-md mx-auto px-2 pt-2">
                <NavItem tab={TabView.DASHBOARD} icon={LayoutDashboard} label="Home" />
                <NavItem tab={TabView.SEND} icon={Send} label="Send" />
                <NavItem tab={TabView.RECEIVE} icon={Download} label="Receive" />
                <NavItem tab={TabView.STAKING} icon={TrendingUp} label="Stake" />
                <NavItem tab={TabView.HISTORY} icon={History} label="History" />
            </div>
        </div>
    );
};
