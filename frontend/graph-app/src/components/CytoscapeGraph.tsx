import React, { useEffect, useRef, useState } from 'react';
import cytoscape, { Core, EventObject } from 'cytoscape';
import { ZoomIn, ZoomOut, Maximize2, Search, RefreshCw, Layers } from 'lucide-react';

interface CytoscapeGraphProps {
  elements: {
    nodes: any[];
    edges: any[];
  };
  onSelectNode: (nodeData: any) => void;
  onSelectEdge: (edgeData: any) => void;
  onClearSelection: () => void;
  isLoading?: boolean;
}

export const CytoscapeGraph: React.FC<CytoscapeGraphProps> = ({
  elements,
  onSelectNode,
  onSelectEdge,
  onClearSelection,
  isLoading = false,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [layoutName, setLayoutName] = useState<'concentric' | 'circle' | 'grid' | 'cose'>('concentric');

  // Initialize and update Cytoscape
  useEffect(() => {
    if (!containerRef.current) return;

    // Build elements payload
    const cyElements = [
      ...elements.nodes.map((n) => ({
        group: 'nodes' as const,
        data: n.data,
      })),
      ...elements.edges.map((e) => ({
        group: 'edges' as const,
        data: e.data,
      })),
    ];

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements: cyElements,
      style: [
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'color': '#cbd5e1',
            'font-size': '10px',
            'font-family': 'Plus Jakarta Sans, sans-serif',
            'text-valign': 'bottom',
            'text-margin-y': 5,
            'background-color': '#0ea5e9',
            'border-width': 2,
            'border-color': '#38bdf8',
            'width': 'data(size)',
            'height': 'data(size)',
            'transition-property': 'background-color, line-color, target-arrow-color, opacity, border-color',
            'transition-duration': 200,
          },
        },
        // Node Severity Colorings
        {
          selector: 'node[severity = "CRITICAL"]',
          style: {
            'background-color': '#ef4444',
            'border-color': '#f87171',
            'shadow-blur': 12,
            'shadow-color': '#ef4444',
            'shadow-opacity': 0.8,
          },
        },
        {
          selector: 'node[severity = "HIGH"]',
          style: {
            'background-color': '#f59e0b',
            'border-color': '#fbbf24',
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
          selector: 'node[type = "internal_service"]',
          style: {
            'shape': 'round-rectangle',
          },
        },
        {
          selector: 'node[type ^= "external"]',
          style: {
            'shape': 'diamond',
          },
        },
        // Edge Styling
        {
          selector: 'edge',
          style: {
            'width': 'data(width)',
            'line-color': '#334155',
            'target-arrow-color': '#334155',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 1.1,
            'opacity': 0.75,
          },
        },
        {
          selector: 'edge[risk_score >= 80]',
          style: {
            'line-color': '#ef4444',
            'target-arrow-color': '#ef4444',
            'opacity': 0.95,
          },
        },
        {
          selector: 'edge[risk_score >= 50][risk_score < 80]',
          style: {
            'line-color': '#f59e0b',
            'target-arrow-color': '#f59e0b',
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
            'border-width': 4,
            'border-color': '#38bdf8',
            'z-index': 999,
          },
        },
        {
          selector: '.dimmed',
          style: {
            'opacity': 0.15,
          },
        },
      ],
      layout: {
        name: layoutName,
        animate: true,
        animationDuration: 400,
      },
    });

    // Tap on node
    cy.on('tap', 'node', (evt: EventObject) => {
      const node = evt.target;
      cy.elements().removeClass('highlighted dimmed');
      const neighborhood = node.neighborhood().add(node);
      cy.elements().difference(neighborhood).addClass('dimmed');
      neighborhood.addClass('highlighted');
      onSelectNode(node.data());
    });

    // Tap on edge
    cy.on('tap', 'edge', (evt: EventObject) => {
      const edge = evt.target;
      cy.elements().removeClass('highlighted dimmed');
      edge.addClass('highlighted');
      edge.connectedNodes().addClass('highlighted');
      onSelectEdge(edge.data());
    });

    // Tap background
    cy.on('tap', (evt: EventObject) => {
      if (evt.target === cy) {
        cy.elements().removeClass('highlighted dimmed');
        onClearSelection();
      }
    });

    cyRef.current = cy;

    return () => {
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
      onSelectNode(matched.first().data());
    }
  };

  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.25);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  const handleFit = () => cyRef.current?.fit(undefined, 30);

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%', overflow: 'hidden' }}>
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
              style={{ paddingLeft: 30, width: 220, height: 34 }}
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
            }}
          >
            Find
          </button>
        </form>

        <select
          value={layoutName}
          onChange={(e) => setLayoutName(e.target.value as any)}
          style={{ height: 34 }}
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
          background: 'var(--bg-surface)',
          padding: 6,
          borderRadius: 8,
          border: '1px solid var(--border-color)',
        }}
      >
        <button
          onClick={handleZoomIn}
          title="Zoom In"
          style={{ background: 'transparent', color: 'var(--text-primary)', padding: 6, borderRadius: 4 }}
        >
          <ZoomIn size={18} />
        </button>
        <button
          onClick={handleZoomOut}
          title="Zoom Out"
          style={{ background: 'transparent', color: 'var(--text-primary)', padding: 6, borderRadius: 4 }}
        >
          <ZoomOut size={18} />
        </button>
        <button
          onClick={handleFit}
          title="Reset View"
          style={{ background: 'transparent', color: 'var(--accent-cyan)', padding: 6, borderRadius: 4 }}
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
          background: 'rgba(11, 19, 43, 0.88)',
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
        <div style={{ fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
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
          <span>■ Box: Internal</span>
          <span>◆ Diamond: External Cloud</span>
        </div>
      </div>

      {/* Main Cytoscape Canvas */}
      <div ref={containerRef} style={{ width: '100%', height: '100%', background: '#070d1e' }} />

      {/* Loading Overlay */}
      {isLoading && (
        <div
          style={{
            position: 'absolute',
            inset: 0,
            background: 'rgba(7, 13, 30, 0.75)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 12,
            zIndex: 20,
          }}
        >
          <RefreshCw className="animate-spin" size={24} style={{ color: 'var(--accent-cyan)' }} />
          <span style={{ fontWeight: 600 }}>Aggregating Network Topology...</span>
        </div>
      )}
    </div>
  );
};
