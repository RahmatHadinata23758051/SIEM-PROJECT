import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import App from './App.tsx';
import './index.css';
import { SIEMProvider } from './hooks/useSIEMStream';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <SIEMProvider>
      <App />
    </SIEMProvider>
  </StrictMode>,
);
