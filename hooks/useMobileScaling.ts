import { useEffect } from 'react';
import { isMobileOrTablet } from '../utils/device';

// Reference resolution: 360x800 (9:20 aspect ratio)
// This roughly corresponds to standard modern Android/iOS viewports (e.g. 1080x2400 @ 3x)
const REF_WIDTH = 360;
const REF_HEIGHT = 800;
const BASE_FONT_size = 16; // Standard browser default

export const useMobileScaling = () => {
    useEffect(() => {
        const handleResize = () => {
            // Check if we should even apply scaling
            // We allow scaling if:
            // 1. It is detected as a mobile/tablet device
            // 2. OR the window width is small (<= 768px) - this covers emulators and resizing desktop windows
            const isSmallScreen = window.innerWidth <= 768;

            if (!isMobileOrTablet && !isSmallScreen) {
                document.documentElement.style.removeProperty('font-size');
                return;
            }

            const width = textWidth();
            const height = window.innerHeight;

            // We want to scale based on whichever dimension is the limiting factor compared to our reference.
            // 1. Width Scale: How does current width compare to 360?
            const scaleX = width / REF_WIDTH;

            // 2. Height Scale: How does current height compare to 800?
            const scaleY = height / REF_HEIGHT;

            // To ensure content fits (prevent cutoff), we must use the SMALLER scale.
            // e.g. 360x640 (Short screen):
            // scaleX = 1
            // scaleY = 0.8
            // scale = 0.8 -> Font size becomes 12.8px.
            // Result: UI shrinks vertically to fit the 640px height.
            // Width (360px) will effectively "feel" wider (like 450px of content space), because 1rem is smaller.
            const scale = Math.min(scaleX, scaleY);

            // Cap scale at 1.15 to avoid things getting TOO big on huge phones,
            // but allow it to shrink as much as needed.
            // const finalScale = Math.min(scale, 1.15); // Optional cap? User said "Scale up too".

            // Apply new root font size
            const newFontSize = BASE_FONT_size * scale;
            document.documentElement.style.fontSize = `${newFontSize}px`;
        };

        // Helper to generic width that ignores scrollbars if possible, though on mobile usually overlay
        function textWidth() {
            return window.innerWidth;
        }

        window.addEventListener('resize', handleResize);
        window.addEventListener('orientationchange', handleResize);

        // Initial call
        handleResize();

        return () => {
            window.removeEventListener('resize', handleResize);
            window.removeEventListener('orientationchange', handleResize);
            // Reset on cleanup (e.g. if navigating away or component unmounts)
            document.documentElement.style.removeProperty('font-size');
        };
    }, []);
};
