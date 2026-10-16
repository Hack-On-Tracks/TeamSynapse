import React, { useState, useEffect } from 'react';
import { WorkspaceView } from './components/WorkspaceView';
import { AuthView, UserSession } from './components/AuthView';

// Default mock elements when backend is spinning up or offline
export const DEFAULT_FALLBACK_ELEMENTS = {
  nodes: [
    { data: { id: 'usr-analyst-01', label: 'E049 (Fin Analyst)', type: 'user', riskScore: 84.5, totalBytes: 850000000, assetTier: 3, firstSeen: '2026-10-14 08:00', lastSeen: '2026-10-15 03:15' } },
    { data: { id: 'usr-engineer-02', label: 'E102 (DevOps Lead)', type: 'user', riskScore: 18.2, totalBytes: 34000000, assetTier: 2, firstSeen: '2026-10-14 09:30', lastSeen: '2026-10-15 11:00' } },
    { data: { id: 'usr-hr-03', label: 'E012 (HR Specialist)', type: 'user', riskScore: 12.0, totalBytes: 12000000, assetTier: 1, firstSeen: '2026-10-14 08:45', lastSeen: '2026-10-15 17:00' } },
    { data: { id: 'srv-dc-01', label: 'dc01.corp.internal', type: 'internal_server', riskScore: 45.0, totalBytes: 920000000, assetTier: 3, firstSeen: '2026-10-01 00:00', lastSeen: '2026-10-15 12:00' } },
    { data: { id: 'srv-dns-01', label: 'dns01.resolver.local', type: 'dns_resolver', riskScore: 15.0, totalBytes: 15000000, assetTier: 2, firstSeen: '2026-10-01 00:00', lastSeen: '2026-10-15 12:00' } },
    { data: { id: 'ext-s3-exfil', label: 'backup-sync.storage.example.net', type: 'cloud_saas', riskScore: 92.0, totalBytes: 820000000, assetTier: 1, isExternal: true, firstSeen: '2026-10-15 02:30', lastSeen: '2026-10-15 03:15' } },
    { data: { id: 'ext-github', label: 'api.github.com', type: 'cloud_saas', riskScore: 5.0, totalBytes: 25000000, assetTier: 1, isExternal: true, firstSeen: '2026-10-01 00:00', lastSeen: '2026-10-15 11:30' } },
    { data: { id: 'ext-workday', label: 'workday.saas.corp', type: 'cloud_saas', riskScore: 8.0, totalBytes: 9000000, assetTier: 1, isExternal: true, firstSeen: '2026-10-01 00:00', lastSeen: '2026-10-15 16:45' } },
  ],
  edges: [
    { data: { id: 'flow-e1', source: 'usr-analyst-01', target: 'ext-s3-exfil', flowsCount: 42, totalBytes: 820000000, riskScore: 92.0, protocol: 'QUIC/TLS', app: 'Cloud Storage', firstSeen: '2026-10-15 02:30', lastSeen: '2026-10-15 03:15' } },
    { data: { id: 'flow-e2', source: 'usr-analyst-01', target: 'srv-dc-01', flowsCount: 15, totalBytes: 45000000, riskScore: 68.0, protocol: 'Kerberos/SMB', app: 'Active Directory', firstSeen: '2026-10-15 01:45', lastSeen: '2026-10-15 02:15' } },
    { data: { id: 'flow-e3', source: 'usr-engineer-02', target: 'ext-github', flowsCount: 120, totalBytes: 25000000, riskScore: 8.0, protocol: 'HTTPS', app: 'Code Repository', firstSeen: '2026-10-14 09:30', lastSeen: '2026-10-15 11:00' } },
    { data: { id: 'flow-e4', source: 'usr-hr-03', target: 'ext-workday', flowsCount: 88, totalBytes: 9000000, riskScore: 5.0, protocol: 'HTTPS', app: 'HR Portal', firstSeen: '2026-10-14 08:45', lastSeen: '2026-10-15 17:00' } },
    { data: { id: 'flow-e5', source: 'usr-analyst-01', target: 'srv-dns-01', flowsCount: 310, totalBytes: 1500000, riskScore: 55.0, protocol: 'DNS', app: 'Domain Resolution', firstSeen: '2026-10-15 01:30', lastSeen: '2026-10-15 03:00' } },
  ],
};

export const App: React.FC = () => {
  const [elements, setElements] = useState(DEFAULT_FALLBACK_ELEMENTS);
  const [apiConnected, setApiConnected] = useState<boolean>(false);

  // Authenticated user session state backed by localStorage
  const [currentUser, setCurrentUser] = useState<UserSession | null>(() => {
    try {
      const stored = localStorage.getItem('ciphersentinel_user') || sessionStorage.getItem('ciphersentinel_user');
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  });

  // Fetch live elements from backend
  const fetchGraphElements = async () => {
    try {
      const res = await fetch('/api/graph/elements');
      if (res.ok) {
        const data = await res.json();
        if (data.nodes && data.nodes.length > 0) {
          setElements(data);
          setApiConnected(true);
          return;
        }
      }
      // Fallback direct check
      const directRes = await fetch('http://127.0.0.1:8000/graph/elements');
      if (directRes.ok) {
        const directData = await directRes.json();
        if (directData.nodes && directData.nodes.length > 0) {
          setElements(directData);
          setApiConnected(true);
        }
      }
    } catch {
      setApiConnected(false);
    }
  };

  useEffect(() => {
    fetchGraphElements();
  }, []);

  const handleLoginSuccess = (user: UserSession) => {
    setCurrentUser(user);
    fetchGraphElements();
  };

  const handleLogout = () => {
    localStorage.removeItem('ciphersentinel_user');
    localStorage.removeItem('ciphersentinel_token');
    sessionStorage.removeItem('ciphersentinel_user');
    sessionStorage.removeItem('ciphersentinel_token');
    setCurrentUser(null);
  };

  // If not authenticated, render Login / Registration Enclave
  if (!currentUser) {
    return <AuthView onLoginSuccess={handleLoginSuccess} />;
  }

  // Once authenticated, render full Workspace Suite
  return (
    <WorkspaceView
      graphElements={elements}
      onRefreshGraph={fetchGraphElements}
      apiConnected={apiConnected}
      currentUser={currentUser}
      onLogout={handleLogout}
    />
  );
};

export default App;
