import React, { useState, useEffect } from 'react';
import { isMobile, isTablet, isIPad13 } from 'react-device-detect';

// Device detection helpers
const isTabletDevice = isTablet || isIPad13;
const isMobileOrTablet = isMobile || isTabletDevice;

interface HeaderProps {
  showNav?: boolean;
}

export const Header: React.FC<HeaderProps> = ({ showNav = true }) => {
  const [menuOpen, setMenuOpen] = useState(false);
  const [price, setPrice] = useState<string | null>(null);

  // Strictly hide on mobile and tablet devices
  if (isMobileOrTablet) return null;


  // Fetch price from Explorer API
  useEffect(() => {
    const fetchPrice = async () => {
      try {
        // Use relative path to avoid hardcoding production URL
        // If running locally, Vite proxy or server.cjs should handle this
        const response = await fetch('/api/price');
        const data = await response.json();
        if (data.price) {
          setPrice(parseFloat(data.price).toFixed(4));
        }
      } catch (e) {
        console.error('Failed to fetch price:', e);
      }
    };

    fetchPrice();
    // Refresh every 60 seconds
    const interval = setInterval(fetchPrice, 60000);
    return () => clearInterval(interval);
  }, []);

  const navItems = [
    { label: 'Home', href: 'https://salvium.tools/', active: false },
    { label: 'Blocks', href: 'https://salvium.tools/blocks', active: false },
    { label: 'Transactions', href: 'https://salvium.tools/transactions', active: false },
    { label: 'Staking', href: 'https://salvium.tools/staking', active: false },
    { label: 'Vault', href: '/vault/', active: true },
    { label: 'Pools', href: 'https://miningpoolstats.stream/salvium', active: false, external: true },
  ];

  return (
    <header className="hidden lg:block bg-dark-900/95 border-b border-dark-700 sticky top-0 z-50 backdrop-blur-md">
      <div className="max-w-[1400px] mx-auto px-4 md:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <a href="/vault/" className="flex items-center gap-3 text-dark-400 hover:text-dark-400 no-underline z-50">
            <img
              src="/vault/assets/img/salvium.png"
              alt="Salvium"
              className="w-8 h-8"
            />
            <span className="font-mono font-semibold text-xl hidden sm:inline">SALVIUM VAULT</span>
          </a>

          {/* Desktop Navigation */}
          {showNav && (
            <nav className="hidden md:flex items-center gap-8">
              {navItems.map((item) => (
                <a
                  key={item.label}
                  href={item.href}
                  target={item.external ? '_blank' : undefined}
                  rel={item.external ? 'noopener noreferrer' : undefined}
                  className={`text-[0.95rem] font-medium transition-colors ${item.active
                    ? 'text-salvium-primary'
                    : 'text-dark-500 hover:text-salvium-primary'
                    }`}
                >
                  {item.label}
                </a>
              ))}

              {/* Price Badge */}
              {price && (
                <div className="bg-gradient-to-r from-salvium-primary to-salvium-secondary text-white px-4 py-2 rounded-md font-mono font-semibold text-[0.95rem]">
                  ${price}
                </div>
              )}
            </nav>
          )}

          {/* Mobile Menu Toggle - REMOVED for strict device detection */}

        </div>

        {/* Mobile Navigation */}
        {showNav && menuOpen && (
          <nav className="md:hidden py-4 border-t border-dark-700">
            <div className="flex flex-col gap-4">
              {navItems.map((item) => (
                <a
                  key={item.label}
                  href={item.href}
                  target={item.external ? '_blank' : undefined}
                  rel={item.external ? 'noopener noreferrer' : undefined}
                  className={`text-sm font-medium transition-colors py-2 ${item.active
                    ? 'text-salvium-primary'
                    : 'text-dark-500 hover:text-salvium-primary'
                    }`}
                  onClick={() => setMenuOpen(false)}
                >
                  {item.label}
                </a>
              ))}
            </div>
          </nav>
        )}
      </div>
    </header>
  );
};
