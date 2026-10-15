import React, { useEffect, useRef, useState } from 'react';
import cytoscape, { Core, EventObject } from 'cytoscape';
import { ZoomIn, ZoomOut, Maximize2, Search, RefreshCw, Layers } from 'lucide-react';

interface CytoscapeGraphProps {
  elements: {
    nodes: any[];
    edges: any[];
  };
  onSelectNode?: (nodeData: any) => void;
  onSelectEdge?: (edgeData: any) => void;
  onNodeSelect?: (nodeData: any) => void;
  onEdgeSelect?: (edgeData: any) => void;
  onClearSelection?: () => void;
  isLoading?: boolean;
  filterRiskThreshold?: number;
  selectedNodeType?: string;
}

export const CytoscapeGraph: React.FC<CytoscapeGraphProps> = ({
  elements,
  onSelectNode,
  onSelectEdge,
  onNodeSelect,
  onEdgeSelect,
  onClearSelection,
  isLoading = false,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [layoutName, setLayoutName] = useState<'cose' | 'concentric' | 'circle' | 'grid'>('cose');

  const handleNodeSelect = onSelectNode || onNodeSelect || (() => {});
  const handleEdgeSelect = onSelectEdge || onEdgeSelect || (() => {});
  const handleClearSelection = onClearSelection || (() => {});

  // Initialize and update Cytoscape
  useEffect(() => {
    if (!containerRef.current) return;

    // Build elements payload with guaranteed fallback sizes and colors
    const cyElements = [
      ...(elements.nodes || []).map((n) => {
        const d = n.data || n;
        const risk = Number(d.riskScore ?? d.risk_score ?? 15);
        const nodeSize = d.size || Math.max(34, Math.min(62, 30 + (risk / 100) * 30));
        const severity = d.severity || (risk >= 80 ? 'CRITICAL' : risk >= 60 ? 'HIGH' : risk >= 35 ? 'MEDIUM' : 'LOW');
        
        return {
          group: 'nodes' as const,
          data: {
            ...d,
            id: String(d.id),
            label: d.label || d.id,
            size: nodeSize,
            severity,
            risk_score: risk,
            riskScore: risk,
          },
        };
      }),
      ...(elements.edges || []).map((e) => {
        const d = e.data || e;
        const risk = Number(d.riskScore ?? d.risk_score ?? 10);
        const edgeWidth = d.width || Math.max(2.5, Math.min(8, 2 + (risk / 100) * 5));
        
        return {
          group: 'edges' as const,
          data: {
            ...d,
            id: String(d.id || `${d.source}-${d.target}`),
            source: String(d.source),
            target: String(d.target),
            width: edgeWidth,
            risk_score: risk,
            riskScore: risk,
            label: d.label || (d.protocol ? `${d.protocol}` : ''),
          },
        };
      }),
    ];

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements: cyElements,
      boxSelectionEnabled: false,
      autounselectify: false,
      style: [
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'color': '#f8fafc',
            'font-size': '11px',
            'font-weight': 600,
            'font-family': 'Plus Jakarta Sans, sans-serif',
            'text-valign': 'bottom',
            'text-margin-y': 7,
            'background-color': '#0ea5e9',
            'border-width': 2.5,
            'border-color': '#38bdf8',
            'width': 'data(size)',
            'height': 'data(size)',
            'text-background-opacity': 0.85,
            'text-background-color': '#060b17',
            'text-background-padding': '3px',
            'text-background-shape': 'roundrectangle',
            'text-border-opacity': 0.5,
            'text-border-width': 1,
            'text-border-color': '#1e293b',
            'transition-property': 'background-color, line-color, target-arrow-color, opacity, border-color, border-width',
            'transition-duration': 200,
          },
        },
        // Node Severity Colorings
        {
          selector: 'node[severity = "CRITICAL"]',
          style: {
            'background-color': '#ef4444',
            'border-color': '#f87171',
            'shadow-blur': 16,
            'shadow-color': '#ef4444',
            'shadow-opacity': 0.9,
          },
        },
        {
          selector: 'node[severity = "HIGH"]',
          style: {
            'background-color': '#f59e0b',
            'border-color': '#fbbf24',
            'shadow-blur': 10,
            'shadow-color': '#f59e0b',
            'shadow-opacity': 0.6,
          },
        },
        {
          selector: 'node[severity = "MEDIUM"]',
          style: {
            'background-color': '#38bdf8',
            'border-color': '#7dd3fc',
          },
        },
        {
          selector: 'node[severity = "LOW"]',
          style: {
            'background-color': '#10b981',
            'border-color': '#34d399',
          },
        },
        // Node Type Shapes
        {
          selector: 'node[type = "internal_server"], node[type = "internal_service"]',
          style: {
            'shape': 'round-rectangle',
          },
        },
        {
          selector: 'node[type = "dns_resolver"]',
          style: {
            'shape': 'hexagon',
          },
        },
        {
          selector: 'node[type ^= "cloud"], node[type ^= "external"]',
          style: {
            'shape': 'diamond',
            'background-color': '#ec4899',
            'border-color': '#f472b6',
          },
        },
        // Edge Styling
        {
          selector: 'edge',
          style: {
            'width': 'data(width)',
            'line-color': '#475569',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 1.25,
            'opacity': 0.8,
            'line-cap': 'round',
          },
        },
        {
          selector: 'edge[risk_score >= 80], edge[riskScore >= 80]',
          style: {
            'line-color': '#ef4444',
            'target-arrow-color': '#ef4444',
            'width': 5,
            'opacity': 1.0,
            'shadow-blur': 8,
            'shadow-color': '#ef4444',
            'shadow-opacity': 0.8,
          },
        },
        {
          selector: 'edge[risk_score >= 50][risk_score < 80], edge[riskScore >= 50][riskScore < 80]',
          style: {
            'line-color': '#f59e0b',
            'target-arrow-color': '#f59e0b',
            'width': 3.5,
            'opacity': 0.95,
          },
        },
        {
          selector: 'edge[?allowlisted]',
          style: {
            'line-style': 'dashed',
            'line-color': '#10b981',
            'target-arrow-color': '#10b981',
          },
        },
        // Selection & Highlight Styles
        {
          selector: '.highlighted',
          style: {
            'opacity': 1.0,
            'border-width': 4.5,
            'border-color': '#38bdf8',
            'z-index': 999,
          },
        },
        {
          selector: '.dimmed',
          style: {
            'opacity': 0.18,
          },
        },
      ],
      layout: {
        name: layoutName,
        animate: true,
        animationDuration: 350,
        padding: 60,
        ...(layoutName === 'cose'
          ? {
              idealEdgeLength: 140,
              nodeOverlap: 30,
              nodeRepulsion: 600000,
              gravity: 60,
              numIter: 1000,
            }
          : {}),
      },
    });

    // Ensure layout fit and resize run cleanly
    cy.on('layoutstop', () => {
      cy.resize();
      cy.fit(undefined, 60);
      cy.center();
    });

    cy.ready(() => {
      cy.resize();
      cy.fit(undefined, 60);
      cy.center();
    });

    const timer = setTimeout(() => {
      if (!cy.isDestroyed()) {
        cy.resize();
        cy.fit(undefined, 60);
        cy.center();
      }
    }, 250);

    const handleWindowResize = () => {
      if (cyRef.current && !cyRef.current.isDestroyed()) {
        cyRef.current.resize();
        cyRef.current.fit(undefined, 60);
        cyRef.current.center();
      }
    };
    window.addEventListener('resize', handleWindowResize);

    // Tap on node
    cy.on('tap', 'node', (evt: EventObject) => {
      const node = evt.target;
      cy.elements().removeClass('highlighted dimmed');
      const neighborhood = node.neighborhood().add(node);
      cy.elements().difference(neighborhood).addClass('dimmed');
      neighborhood.addClass('highlighted');
      handleNodeSelect(node.data());
    });

    // Tap on edge
    cy.on('tap', 'edge', (evt: EventObject) => {
      const edge = evt.target;
      cy.elements().removeClass('highlighted dimmed');
      edge.addClass('highlighted');
      edge.connectedNodes().addClass('highlighted');
      handleEdgeSelect(edge.data());
    });

    // Tap background
    cy.on('tap', (evt: EventObject) => {
      if (evt.target === cy) {
        cy.elements().removeClass('highlighted dimmed');
        handleClearSelection();
      }
    });

    cyRef.current = cy;

    return () => {
      clearTimeout(timer);
      window.removeEventListener('resize', handleWindowResize);
      cy.destroy();
      cyRef.current = null;
    };
  }, [elements, layoutName]);

  // Handle Search & Focus
  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (!cyRef.current || !searchTerm.trim()) return;
    const cy = cyRef.current;
    const matched = cy.nodes().filter((n) => {
      const id = String(n.data('id') || '').toLowerCase();
      const label = String(n.data('label') || '').toLowerCase();
      const term = searchTerm.toLowerCase();
      return id.includes(term) || label.includes(term);
    });

    if (matched.length > 0) {
      cy.elements().removeClass('highlighted dimmed');
      matched.addClass('highlighted');
      matched.neighborhood().addClass('highlighted');
      cy.elements().difference(matched.neighborhood().add(matched)).addClass('dimmed');
      cy.animate({
        center: { eles: matched.first() },
        zoom: 1.8,
        duration: 500,
      });
      handleNodeSelect(matched.first().data());
    }
  };

  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.25);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  const handleFit = () => {
    cyRef.current?.resize();
    cyRef.current?.fit(undefined, 45);
  };

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%', minHeight: '580px', overflow: 'hidden', background: '#060b17' }}>
      {/* Top Floating Toolbar */}
      <div
        style={{
          position: 'absolute',
          top: 16,
          left: 16,
          zIndex: 10,
          display: 'flex',
          gap: 10,
          alignItems: 'center',
        }}
      >
        <form onSubmit={handleSearch} style={{ display: 'flex', gap: 6 }}>
          <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
            <Search size={14} style={{ position: 'absolute', left: 10, color: 'var(--text-muted)' }} />
            <input
              type="text"
              placeholder="Search Entity / IP..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                paddingLeft: 30,
                width: 220,
                height: 34,
                background: 'rgba(11, 21, 43, 0.9)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-color)',
                borderRadius: 6,
                fontSize: '0.8rem',
              }}
            />
          </div>
          <button
            type="submit"
            style={{
              background: 'var(--bg-card)',
              color: 'var(--accent-cyan)',
              border: '1px solid var(--border-color)',
              borderRadius: 6,
              padding: '0 12px',
              height: 34,
              fontSize: '0.8rem',
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Find
          </button>
        </form>

        <select
          value={layoutName}
          onChange={(e) => setLayoutName(e.target.value as any)}
          style={{
            height: 34,
            background: 'rgba(11, 21, 43, 0.9)',
            color: 'var(--text-primary)',
            border: '1px solid var(--border-color)',
            borderRadius: 6,
            padding: '0 10px',
            fontSize: '0.8rem',
            cursor: 'pointer',
          }}
        >
          <option value="concentric">Concentric Layout</option>
          <option value="cose">Force-Directed (COSE)</option>
          <option value="circle">Circular Layout</option>
          <option value="grid">Grid Layout</option>
        </select>
      </div>

      {/* Floating Canvas Navigation Controls */}
      <div
        style={{
          position: 'absolute',
          bottom: 24,
          right: 24,
          zIndex: 10,
          display: 'flex',
          flexDirection: 'column',
          gap: 6,
          background: 'rgba(11, 21, 43, 0.9)',
          backdropFilter: 'blur(8px)',
          padding: 6,
          borderRadius: 8,
          border: '1px solid var(--border-color)',
        }}
      >
        <button
          onClick={handleZoomIn}
          title="Zoom In"
          style={{ background: 'transparent', color: 'var(--text-primary)', padding: 6, borderRadius: 4, cursor: 'pointer', border: 'none' }}
        >
          <ZoomIn size={18} />
        </button>
        <button
          onClick={handleZoomOut}
          title="Zoom Out"
          style={{ background: 'transparent', color: 'var(--text-primary)', padding: 6, borderRadius: 4, cursor: 'pointer', border: 'none' }}
        >
          <ZoomOut size={18} />
        </button>
        <button
          onClick={handleFit}
          title="Reset View"
          style={{ background: 'transparent', color: 'var(--accent-cyan)', padding: 6, borderRadius: 4, cursor: 'pointer', border: 'none' }}
        >
          <Maximize2 size={18} />
        </button>
      </div>

      {/* Floating SOC Legend */}
      <div
        style={{
          position: 'absolute',
          bottom: 24,
          left: 24,
          zIndex: 10,
          background: 'rgba(11, 21, 43, 0.9)',
          backdropFilter: 'blur(8px)',
          padding: '10px 14px',
          borderRadius: 8,
          border: '1px solid var(--border-color)',
          fontSize: '0.75rem',
          display: 'flex',
          flexDirection: 'column',
          gap: 6,
        }}
      >
        <div style={{ fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Topology Legend
        </div>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#ef4444' }}></span> Critical
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#f59e0b' }}></span> High
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#38bdf8' }}></span> Medium
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#10b981' }}></span> Low
          </span>
        </div>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', color: 'var(--text-muted)' }}>
          <span>● Circle: Endpoint</span>
          <span>■ Box: Server</span>
          <span>◆ Diamond: Cloud SaaS</span>
        </div>
      </div>

      {/* Main Cytoscape Canvas */}
      <div ref={containerRef} style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', background: '#060b17' }} />

      {/* Loading Overlay */}
      {isLoading && (
        <div
          style={{
            position: 'absolute',
            inset: 0,
            background: 'rgba(6, 11, 23, 0.85)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 12,
            zIndex: 20,
          }}
        >
          <RefreshCw className="animate-spin" size={24} style={{ color: 'var(--accent-cyan)' }} />
          <span style={{ fontWeight: 600, color: '#f8fafc' }}>Aggregating Network Topology...</span>
        </div>
      )}
    </div>
  );
};
