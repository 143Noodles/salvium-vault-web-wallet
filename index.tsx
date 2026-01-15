import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';

// Initialize i18n before app renders
import './i18n';

import PWAOnlyGate from './components/PWAOnlyGate';

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error("Could not find root element to mount to");
}

const root = ReactDOM.createRoot(rootElement);
root.render(
  <React.StrictMode>
    <PWAOnlyGate>
      <App />
    </PWAOnlyGate>
  </React.StrictMode>
);