import React, { useEffect, useRef, useState } from 'react';
import {
  Globe2,
  Navigation,
  Layers,
  MapPin,
  Play,
  Pause,
  Send,
  ShieldAlert,
  Zap,
  Activity,
  Maximize2,
  RefreshCw,
} from '../icons';

// Declare Leaflet global type from CDN script
declare const L: any;

interface DestinationIP {
  id: string;
  ip: string;
  hostname: string;
  city: string;
  country: string;
  lat: number;
  lng: number;
  protocol: string;
  riskScore: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  bytesAvg: number;
}

const GLOBAL_DESTINATIONS: DestinationIP[] = [
  {
    id: 'dst-tokyo',
    ip: '203.0.113.14',
    hostname: 'gfs270n113.userstorage.mega.co.nz',
    city: 'Tokyo',
    country: 'Japan',
    lat: 35.6762,
    lng: 139.6503,
    protocol: 'QUIC / UDP 443',
    riskScore: 96,
    severity: 'CRITICAL',
    category: 'Personal Cloud Exfiltration',
    bytesAvg: 34500000,
  },
  {
    id: 'dst-frankfurt',
    ip: '198.51.100.18',
    hostname: 'content.dropboxapi.com',
    city: 'Frankfurt',
    country: 'Germany',
    lat: 50.1109,
    lng: 8.6821,
    protocol: 'TLS / TCP 443',
    riskScore: 84,
    severity: 'HIGH',
    category: 'Volumetric Cloud Sync',
    bytesAvg: 28900000,
  },
  {
    id: 'dst-amsterdam',
    ip: '185.220.101.5',
    hostname: 'c2-beacon.tunnel-edge.net',
    city: 'Amsterdam',
    country: 'Netherlands',
    lat: 52.3676,
    lng: 4.9041,
    protocol: 'DNS Tunnel / UDP 53',
    riskScore: 94,
    severity: 'CRITICAL',
    category: 'Suspected C2 Tunnel',
    bytesAvg: 890000,
  },
  {
    id: 'dst-ashburn',
    ip: '52.28.112.50',
    hostname: 'ext-bucket.s3.amazonaws.com',
    city: 'Ashburn, VA',
    country: 'United States',
    lat: 39.0438,
    lng: -77.4874,
    protocol: 'HTTPS / TCP 443',
    riskScore: 78,
    severity: 'HIGH',
    category: 'External S3 Bucket',
    bytesAvg: 19800000,
  },
  {
    id: 'dst-sf',
    ip: '140.82.121.4',
    hostname: 'api.github.com',
    city: 'San Francisco',
    country: 'United States',
    lat: 37.7749,
    lng: -122.4194,
    protocol: 'HTTPS / TCP 443',
    riskScore: 8,
    severity: 'LOW',
    category: 'Developer Code Sync',
    bytesAvg: 4200000,
  },
  {
    id: 'dst-singapore',
    ip: '103.28.248.1',
    hostname: 'proxy.apac.internal.net',
    city: 'Singapore',
    country: 'Singapore',
    lat: 1.3521,
    lng: 103.8198,
    protocol: 'TLS / TCP 8443',
    riskScore: 35,
    severity: 'MEDIUM',
    category: 'Regional Gateway',
    bytesAvg: 15400000,
  },
  {
    id: 'dst-sydney',
    ip: '104.192.141.1',
    hostname: 'jira.atlassian.net',
    city: 'Sydney',
    country: 'Australia',
    lat: -33.8688,
    lng: 151.2093,
    protocol: 'HTTPS / TCP 443',
    riskScore: 10,
    severity: 'LOW',
    category: 'Enterprise SaaS',
    bytesAvg: 24000,
  },
  {
    id: 'dst-saopaulo',
    ip: '200.147.67.1',
    hostname: 'storage-mirror.latam.corp',
    city: 'São Paulo',
    country: 'Brazil',
    lat: -23.5505,
    lng: -46.6333,
    protocol: 'SSH / TCP 22',
    riskScore: 68,
    severity: 'HIGH',
    category: 'Offshore Encrypted Backup',
    bytesAvg: 12500000,
  },
  {
    id: 'dst-london',
    ip: '51.140.10.2',
    hostname: 'portal.azure.com',
    city: 'London',
    country: 'United Kingdom',
    lat: 51.5074,
    lng: -0.1278,
    protocol: 'HTTPS / TCP 443',
    riskScore: 15,
    severity: 'LOW',
    category: 'Cloud Infrastructure',
    bytesAvg: 8900000,
  },
];

export type MapTypeKey = 'dark' | 'satellite' | 'osm' | 'topo' | 'streets' | 'natgeo' | 'ocean' | 'physical' | 'light';

export interface MapTypeConfig {
  id: MapTypeKey;
  label: string;
  category: 'Tactical' | 'Imagery' | 'Street' | 'Terrain' | 'Maritime' | 'Editorial';
  categoryClass: string;
  icon: string;
  providerName: string;
  description: string;
  recommendedFor: string;
  url: string;
  options: any;
}

export const MAP_PROVIDERS: Record<MapTypeKey, MapTypeConfig> = {
  dark: {
    id: 'dark',
    label: 'Cyber Dark Canvas',
    category: 'Tactical',
    categoryClass: 'cat-tactical',
    icon: '🕶️',
    providerName: 'Esri Dark Gray Canvas',
    description: 'High-contrast midnight dark canvas engineered for SOC packet trajectory tracing & nocturnal threat detection.',
    recommendedFor: '24/7 Security Operations & Incident Response Displays',
    url: 'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}',
    options: {
      maxZoom: 16,
      attribution: 'Tiles &copy; Esri &mdash; World Dark Gray Base',
    },
  },
  satellite: {
    id: 'satellite',
    label: 'Satellite Imagery',
    category: 'Imagery',
    categoryClass: 'cat-imagery',
    icon: '🛰️',
    providerName: 'Esri World Imagery',
    description: 'Ultra high-resolution real orbital satellite and aerial photography with seamless global ground coverage.',
    recommendedFor: 'Physical Datacenter Reconnaissance & Real-world Geo Analysis',
    url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
    options: {
      maxZoom: 19,
      attribution: 'Tiles &copy; Esri &mdash; World Imagery',
    },
  },
  osm: {
    id: 'osm',
    label: 'OpenStreetMap',
    category: 'Street',
    categoryClass: 'cat-street',
    icon: '🗺️',
    providerName: 'OpenStreetMap Standard',
    description: 'World-standard collaborative open-source street map with rich municipal data, boundaries, and street networks.',
    recommendedFor: 'Metropolitan Server Host IP Geolocation & Public Verification',
    url: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
    options: {
      maxZoom: 19,
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
    },
  },
  topo: {
    id: 'topo',
    label: 'Topographic Terrain',
    category: 'Terrain',
    categoryClass: 'cat-terrain',
    icon: '🏔️',
    providerName: 'Esri World Topographic',
    description: 'Contour lines, elevation relief shading, mountain ranges, hydrological networks, and geographic landmarks.',
    recommendedFor: 'Regional Physical Infrastructure & Elevation Corridor Tracing',
    url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Topo_Map/MapServer/tile/{z}/{y}/{x}',
    options: {
      maxZoom: 19,
      attribution: 'Tiles &copy; Esri &mdash; World Topographic Map',
    },
  },
  streets: {
    id: 'streets',
    label: 'World Streets',
    category: 'Street',
    categoryClass: 'cat-street',
    icon: '🛣️',
    providerName: 'Esri World Street Map',
    description: 'Comprehensive transport highways, arterial road networks, urban borders, points of interest, and railways.',
    recommendedFor: 'City-level Urban Transit & Ground Node Identification',
    url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/{z}/{y}/{x}',
    options: {
      maxZoom: 19,
      attribution: 'Tiles &copy; Esri &mdash; World Street Map',
    },
  },
  natgeo: {
    id: 'natgeo',
    label: 'National Geographic',
    category: 'Editorial',
    categoryClass: 'cat-editorial',
    icon: '🧭',
    providerName: 'National Geographic Society',
    description: 'Acclaimed National Geographic editorial cartography featuring historic typography, shaded relief, and boundary delineation.',
    recommendedFor: 'Geopolitical Threat Boundary & State-Sponsored Actor Context',
    url: 'https://server.arcgisonline.com/ArcGIS/rest/services/NatGeo_World_Map/MapServer/tile/{z}/{y}/{x}',
    options: {
      maxZoom: 16,
      attribution: 'Tiles &copy; Esri &mdash; National Geographic World Map',
    },
  },
  ocean: {
    id: 'ocean',
    label: 'Ocean Bathymetry',
    category: 'Maritime',
    categoryClass: 'cat-maritime',
    icon: '🌊',
    providerName: 'Esri World Ocean Base',
    description: 'Marine continental shelves, deep sea trenches, bathymetric depth gradients & submarine cable corridors.',
    recommendedFor: 'Transoceanic Submarine Internet Fiber Cable Telemetry',
    url: 'https://server.arcgisonline.com/ArcGIS/rest/services/Ocean/World_Ocean_Base/MapServer/tile/{z}/{y}/{x}',
    options: {
      maxZoom: 13,
      attribution: 'Tiles &copy; Esri &mdash; World Ocean Base',
    },
  },
  physical: {
    id: 'physical',
    label: 'Physical Earth Relief',
    category: 'Terrain',
    categoryClass: 'cat-terrain',
    icon: '🌍',
    providerName: 'Esri World Physical',
    description: 'Natural landcover textures, elevations, desert biomes, vegetation, and shaded continental mountain relief.',
    recommendedFor: 'Geographical Environment & Transcontinental Routing',
    url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Physical_Map/MapServer/tile/{z}/{y}/{x}',
    options: {
      maxZoom: 8,
      attribution: 'Tiles &copy; Esri &mdash; World Physical Map',
    },
  },
  light: {
    id: 'light',
    label: 'Clean Light Canvas',
    category: 'Tactical',
    categoryClass: 'cat-tactical',
    icon: '☀️',
    providerName: 'Esri Light Gray Canvas',
    description: 'Minimalist high-contrast light cartography designed for brightly lit command stations and incident rooms.',
    recommendedFor: 'Daylight Situation Rooms & High-ambient Office Screens',
    url: 'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Light_Gray_Base/MapServer/tile/{z}/{y}/{x}',
    options: {
      maxZoom: 16,
      attribution: 'Tiles &copy; Esri &mdash; World Light Gray Base',
    },
  },
};

export const LiveGeoThreatMap: React.FC = () => {
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapRef = useRef<any>(null);
  const tileLayerRef = useRef<any>(null);
  const packetLinesLayerRef = useRef<any>(null);

  // User's Live Location state (Default to Mumbai / India SOC or browser geolocation)
  const [liveLocation, setLiveLocation] = useState<{ lat: number; lng: number; city: string; accuracy: number }>({
    lat: 19.076,
    lng: 72.8777,
    city: 'Current Sensor Location (HQ)',
    accuracy: 25,
  });
  const [geoStatus, setGeoStatus] = useState<string>('Detecting live geolocation...');
  const [mapMode, setMapMode] = useState<MapTypeKey>('dark');
  const [isStreaming, setIsStreaming] = useState<boolean>(true);
  const [packetCount, setPacketCount] = useState<number>(0);
  const [lastTransmission, setLastTransmission] = useState<any | null>(null);

  // 1. Obtain browser live location
  useEffect(() => {
    if ('geolocation' in navigator) {
      navigator.geolocation.getCurrentPosition(
        position => {
          setLiveLocation({
            lat: position.coords.latitude,
            lng: position.coords.longitude,
            city: 'Live Device Geolocation',
            accuracy: Math.round(position.coords.accuracy),
          });
          setGeoStatus(`🟢 Live GPS Locked (±${Math.round(position.coords.accuracy)}m)`);
        },
        err => {
          setGeoStatus('🌐 Using SOC Primary Network Sensor (19.0760° N, 72.8777° E)');
        },
        { enableHighAccuracy: true, timeout: 8000 }
      );
    } else {
      setGeoStatus('🌐 Using SOC Primary Network Sensor');
    }
  }, []);

  // 2. Initialize Leaflet Map
  useEffect(() => {
    if (!mapContainerRef.current) return;
    if (typeof L === 'undefined') {
      console.warn('Leaflet script still loading from CDN...');
      return;
    }

    if (mapRef.current) {
      mapRef.current.remove();
    }

    const map = L.map(mapContainerRef.current, {
      center: [24.0, 30.0],
      zoom: 2.5,
      minZoom: 2,
      maxZoom: 19,
      zoomControl: false,
      attributionControl: true,
    });

    mapRef.current = map;

    // Add Initial Tile Layer
    const provider = MAP_PROVIDERS[mapMode] || MAP_PROVIDERS.dark;
    tileLayerRef.current = L.tileLayer(provider.url, provider.options).addTo(map);

    // Add Layer Groups for lines & markers
    packetLinesLayerRef.current = L.layerGroup().addTo(map);

    // Zoom control in top right
    L.control.zoom({ position: 'topright' }).addTo(map);

    // Add Leaflet Native Layer Control with all 9 basemaps
    const baseLayers: Record<string, any> = {};
    Object.keys(MAP_PROVIDERS).forEach(key => {
      const p = MAP_PROVIDERS[key as MapTypeKey];
      baseLayers[`${p.icon} ${p.label}`] = L.tileLayer(p.url, p.options);
    });
    L.control.layers(baseLayers, undefined, { position: 'topright', collapsed: true }).addTo(map);

    // Sync external Leaflet layer control changes back to React state
    map.on('baselayerchange', (e: any) => {
      const match = Object.entries(MAP_PROVIDERS).find(([_, v]) => `${v.icon} ${v.label}` === e.name);
      if (match) {
        setMapMode(match[0] as MapTypeKey);
      }
    });

    renderMapMarkers();

    return () => {
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }
    };
  }, []);

  // 3. Switch Tile Layers when mapMode changes
  useEffect(() => {
    if (!mapRef.current || !tileLayerRef.current) return;
    mapRef.current.removeLayer(tileLayerRef.current);
    const provider = MAP_PROVIDERS[mapMode] || MAP_PROVIDERS.dark;
    tileLayerRef.current = L.tileLayer(provider.url, provider.options).addTo(mapRef.current);
    if (tileLayerRef.current.bringToBack) {
      tileLayerRef.current.bringToBack();
    }
  }, [mapMode]);

  // 4. Render Markers and Current Location on Map
  const renderMapMarkers = () => {
    if (!mapRef.current || typeof L === 'undefined') return;

    // Clear previous markers
    if (packetLinesLayerRef.current) {
      packetLinesLayerRef.current.clearLayers();
    }

    // A. Add Current Live Location Beacon Marker
    const sensorIcon = L.divIcon({
      className: 'custom-live-location-pin',
      html: `
        <div style="position: relative; width: 36px; height: 36px;">
          <div style="position: absolute; inset: 0; border-radius: 50%; background: rgba(56, 189, 248, 0.35); animation: ping 2s cubic-bezier(0, 0, 0.2, 1) infinite;"></div>
          <div style="position: absolute; inset: 6px; border-radius: 50%; background: #0284c7; border: 2px solid #38bdf8; display: flex; align-items: center; justify-content: center; box-shadow: 0 0 14px #38bdf8;">
            <div style="width: 8px; height: 8px; border-radius: 50%; background: #ffffff;"></div>
          </div>
        </div>
      `,
      iconSize: [36, 36],
      iconAnchor: [18, 18],
    });

    const sensorMarker = L.marker([liveLocation.lat, liveLocation.lng], { icon: sensorIcon }).addTo(mapRef.current);
    sensorMarker.bindPopup(`
      <div style="font-family: sans-serif; color: #0f172a; font-size: 12px; padding: 4px;">
        <strong style="color: #0284c7; font-size: 13px;">📍 YOUR LIVE SENSOR ORIGIN</strong><br/>
        <b>Coordinates:</b> ${liveLocation.lat.toFixed(4)}°, ${liveLocation.lng.toFixed(4)}°<br/>
        <b>Status:</b> Active Sensor Probe<br/>
        <b>Live Packet Ingestion:</b> 1 packet / 2.0s
      </div>
    `);

    // B. Add Destination Markers
    GLOBAL_DESTINATIONS.forEach(dst => {
      const color =
        dst.severity === 'CRITICAL'
          ? '#ef4444'
          : dst.severity === 'HIGH'
          ? '#f59e0b'
          : dst.severity === 'MEDIUM'
          ? '#38bdf8'
          : '#10b981';

      const dstIcon = L.divIcon({
        className: 'custom-dst-pin',
        html: `
          <div style="position: relative; width: 26px; height: 26px;">
            <div style="position: absolute; inset: 0; border-radius: 50%; background: ${color}; opacity: 0.35; animation: pulse 1.5s infinite;"></div>
            <div style="position: absolute; inset: 4px; border-radius: 50%; background: #070d1e; border: 2px solid ${color}; display: flex; align-items: center; justify-content: center; box-shadow: 0 0 10px ${color};">
              <div style="width: 6px; height: 6px; border-radius: 50%; background: ${color};"></div>
            </div>
          </div>
        `,
        iconSize: [26, 26],
        iconAnchor: [13, 13],
      });

      const m = L.marker([dst.lat, dst.lng], { icon: dstIcon }).addTo(mapRef.current);
      m.bindPopup(`
        <div style="font-family: sans-serif; color: #0f172a; font-size: 12px; padding: 4px; min-width: 180px;">
          <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; margin-bottom: 4px;">
            <strong style="color: ${color};">${dst.city}, ${dst.country}</strong>
            <span style="font-size: 10px; font-weight: bold; background: ${color}20; color: ${color}; padding: 1px 4px; border-radius: 4px;">${dst.severity}</span>
          </div>
          <b>Target IP:</b> <code style="background: #f1f5f9; padding: 1px 4px; border-radius: 3px;">${dst.ip}</code><br/>
          <b>Destination:</b> ${dst.hostname}<br/>
          <b>Protocol:</b> ${dst.protocol}<br/>
          <b>Threat Category:</b> ${dst.category}<br/>
          <b>Risk Score:</b> <strong>${dst.riskScore} / 100</strong>
        </div>
      `);
    });
  };

  // Re-render markers if live location changes
  useEffect(() => {
    if (mapRef.current) {
      renderMapMarkers();
    }
  }, [liveLocation]);

  // 5. Send animated packet along curved trajectory
  const sendLivePacket = () => {
    if (!mapRef.current || typeof L === 'undefined') return;

    // Pick random target weighted toward critical/high
    const target = GLOBAL_DESTINATIONS[Math.floor(Math.random() * GLOBAL_DESTINATIONS.length)];
    const origin = [liveLocation.lat, liveLocation.lng];
    const destination = [target.lat, target.lng];

    // Compute midpoint curved arc coordinate
    const midLat = (origin[0] + destination[0]) / 2 + (destination[1] > origin[1] ? 15 : -15);
    const midLng = (origin[1] + destination[1]) / 2;

    const curvePoints: [number, number][] = [];
    const steps = 30;
    for (let t = 0; t <= 1; t += 1 / steps) {
      // Quadratic Bezier interpolation
      const lat = (1 - t) * (1 - t) * origin[0] + 2 * (1 - t) * t * midLat + t * t * destination[0];
      const lng = (1 - t) * (1 - t) * origin[1] + 2 * (1 - t) * t * midLng + t * t * destination[1];
      curvePoints.push([lat, lng]);
    }

    const strokeColor =
      target.severity === 'CRITICAL' ? '#ef4444' : target.severity === 'HIGH' ? '#f59e0b' : '#38bdf8';

    // Draw trajectory line
    const polyline = L.polyline(curvePoints, {
      color: strokeColor,
      weight: 2.5,
      opacity: 0.75,
      dashArray: '6, 8',
    }).addTo(packetLinesLayerRef.current);

    // Animated packet dot traversing along the curve
    const packetDot = L.circleMarker(origin, {
      radius: 5,
      color: '#ffffff',
      fillColor: strokeColor,
      fillOpacity: 1.0,
      weight: 2,
    }).addTo(packetLinesLayerRef.current);

    let stepIndex = 0;
    const animInterval = setInterval(() => {
      stepIndex++;
      if (stepIndex < curvePoints.length) {
        packetDot.setLatLng(curvePoints[stepIndex]);
      } else {
        clearInterval(animInterval);
        // Remove packet dot and fade polyline after impact
        packetDot.remove();
        setTimeout(() => {
          polyline.remove();
        }, 1200);
      }
    }, 45);

    // Update state & stats
    setPacketCount(prev => prev + 1);
    setLastTransmission({
      target,
      bytes: target.bytesAvg,
      timestamp: new Date().toLocaleTimeString(),
    });
  };

  // 6. 2-Second Live Loop
  useEffect(() => {
    if (!isStreaming) return;
    const interval = setInterval(() => {
      sendLivePacket();
    }, 2000);

    return () => clearInterval(interval);
  }, [isStreaming, liveLocation]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, width: '100%' }}>
      {/* Top Banner & Control Bar */}
      <div
        style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-color)',
          borderRadius: 8,
          padding: '14px 18px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 12,
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Globe2 className="text-cyan-400" size={20} />
            <h2 style={{ fontSize: '1rem', fontWeight: 700, margin: 0, color: 'var(--text-primary)' }}>
              Live Global Cyber Attack & Exfiltration Map
            </h2>
            <span
              style={{
                fontSize: '0.72rem',
                fontWeight: 700,
                padding: '2px 8px',
                borderRadius: 12,
                background: 'rgba(56, 189, 248, 0.15)',
                color: '#38bdf8',
                border: '1px solid rgba(56, 189, 248, 0.4)',
              }}
            >
              LIVE 2.0s INTERVAL
            </span>
          </div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 4, display: 'flex', gap: 16 }}>
            <span>{geoStatus}</span>
            <span>&bull;</span>
            <span>
              Origin Coordinates:{' '}
              <strong style={{ color: '#f8fafc' }}>
                {liveLocation.lat.toFixed(4)}° N, {liveLocation.lng.toFixed(4)}° E
              </strong>
            </span>
            <span>&bull;</span>
            <span>
              Telemetry Stream:{' '}
              <strong style={{ color: isStreaming ? '#34d399' : '#f87171' }}>
                {isStreaming ? 'CONNECTED (2.0s)' : 'PAUSED'}
              </strong>
            </span>
          </div>
        </div>

        {/* Stream Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {/* Stream Toggle */}
          <button
            onClick={() => setIsStreaming(!isStreaming)}
            style={{
              background: isStreaming ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
              color: isStreaming ? '#f87171' : '#34d399',
              border: `1px solid ${isStreaming ? '#ef4444' : '#10b981'}`,
              borderRadius: 6,
              padding: '7px 14px',
              fontSize: '0.78rem',
              fontWeight: 700,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              boxShadow: isStreaming ? '0 0 10px rgba(239, 68, 68, 0.25)' : '0 0 10px rgba(16, 185, 129, 0.25)',
            }}
          >
            {isStreaming ? <Pause size={14} /> : <Play size={14} />}
            {isStreaming ? 'PAUSE STREAM' : 'RESUME STREAM'}
          </button>

          {/* Test Packet */}
          <button
            onClick={sendLivePacket}
            style={{
              background: '#0284c7',
              color: '#ffffff',
              border: 'none',
              borderRadius: 6,
              padding: '7px 14px',
              fontSize: '0.78rem',
              fontWeight: 700,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              boxShadow: '0 0 12px rgba(2, 132, 199, 0.4)',
            }}
          >
            <Send size={14} />
            SEND TEST PACKET
          </button>
        </div>
      </div>

      {/* Cartographic Multi-Engine Selector Gallery */}
      <div className="map-engine-gallery-wrapper">
        <div className="map-gallery-header">
          <div className="map-gallery-title-box">
            <Layers className="text-cyan-400" size={17} />
            <span style={{ fontSize: '0.85rem', fontWeight: 800, color: '#f8fafc', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
              Global Map Cartography Engines
            </span>
            <span className="map-gallery-badge-count">9 Types Available</span>
          </div>
          <div style={{ fontSize: '0.76rem', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: 6 }}>
            <span>Active Layer:</span>
            <strong style={{ color: '#38bdf8' }}>
              {MAP_PROVIDERS[mapMode]?.icon} {MAP_PROVIDERS[mapMode]?.label}
            </strong>
            <span style={{ color: '#475569' }}>|</span>
            <span style={{ color: '#cbd5e1' }}>{MAP_PROVIDERS[mapMode]?.providerName}</span>
          </div>
        </div>

        {/* 9 Map Engine Cards */}
        <div className="map-gallery-grid">
          {(Object.keys(MAP_PROVIDERS) as MapTypeKey[]).map(key => {
            const config = MAP_PROVIDERS[key];
            const isActive = mapMode === key;
            return (
              <div
                key={key}
                onClick={() => setMapMode(key)}
                className={`map-engine-card ${isActive ? 'active-map-card' : ''}`}
                title={config.description}
              >
                {isActive && <div className="map-active-indicator" />}
                <div className="map-card-top">
                  <span className="map-card-icon">{config.icon}</span>
                  <span className={`map-card-cat-badge ${config.categoryClass}`}>{config.category}</span>
                </div>
                <div className="map-card-name" style={{ color: isActive ? '#38bdf8' : '#f8fafc' }}>
                  {config.label}
                </div>
                <div className="map-card-provider">{config.providerName}</div>
              </div>
            );
          })}
        </div>

        {/* Active Map Engine Details Panel */}
        {MAP_PROVIDERS[mapMode] && (
          <div className="map-detail-strip">
            <div className="map-detail-desc">
              <span style={{ fontSize: '1.1rem' }}>{MAP_PROVIDERS[mapMode].icon}</span>
              <span>
                <strong style={{ color: '#38bdf8' }}>{MAP_PROVIDERS[mapMode].label}:</strong>{' '}
                {MAP_PROVIDERS[mapMode].description}
              </span>
            </div>
            <div className="map-detail-meta">
              <span>
                🎯 <strong style={{ color: '#f8fafc' }}>Use Case:</strong> {MAP_PROVIDERS[mapMode].recommendedFor}
              </span>
              <span>&bull;</span>
              <span>
                ⚡ Max Zoom: <strong style={{ color: '#38bdf8' }}>{MAP_PROVIDERS[mapMode].options.maxZoom}x</strong>
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Main Map Container */}
      <div
        style={{
          position: 'relative',
          height: '560px',
          minHeight: '560px',
          borderRadius: 12,
          overflow: 'hidden',
          border: '1px solid var(--border-color)',
          background: '#060b17',
          boxShadow: '0 8px 30px rgba(0, 0, 0, 0.4)',
        }}
      >
        <div ref={mapContainerRef} style={{ width: '100%', height: '100%', zIndex: 1 }} />

        {/* Floating Telemetry HUD Overlay (Top-Left) */}
        <div
          style={{
            position: 'absolute',
            top: 16,
            left: 16,
            zIndex: 10,
            background: 'rgba(6, 11, 23, 0.88)',
            backdropFilter: 'blur(10px)',
            border: '1px solid var(--border-color)',
            borderRadius: 8,
            padding: '12px 16px',
            fontSize: '0.78rem',
            minWidth: 260,
            boxShadow: '0 4px 20px rgba(0,0,0,0.5)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <span style={{ fontWeight: 700, color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              📡 Live Transmission HUD
            </span>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: isStreaming ? '#10b981' : '#64748b' }}></span>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ color: 'var(--text-muted)' }}>Packets Dispatched:</span>
            <strong style={{ color: '#f8fafc' }}>{packetCount}</strong>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ color: 'var(--text-muted)' }}>Interval:</span>
            <strong style={{ color: '#10b981' }}>2.0s Heartbeat</strong>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ color: 'var(--text-muted)' }}>Global Targets:</span>
            <strong style={{ color: '#f8fafc' }}>{GLOBAL_DESTINATIONS.length} International IPs</strong>
          </div>

          {lastTransmission && (
            <div
              style={{
                marginTop: 8,
                paddingTop: 8,
                borderTop: '1px solid rgba(255,255,255,0.1)',
                fontSize: '0.72rem',
              }}
            >
              <div style={{ color: '#94a3b8' }}>Latest Transmission ({lastTransmission.timestamp}):</div>
              <div style={{ color: '#38bdf8', fontWeight: 600, marginTop: 2 }}>
                {lastTransmission.target.city}, {lastTransmission.target.country} ({lastTransmission.target.ip})
              </div>
              <div style={{ color: lastTransmission.target.riskScore >= 80 ? '#ef4444' : '#10b981', fontWeight: 700 }}>
                {lastTransmission.target.category} &bull; {(lastTransmission.bytes / 1024 / 1024).toFixed(1)} MB
              </div>
            </div>
          )}
        </div>

        {/* Floating Map Legend (Bottom-Left) */}
        <div
          style={{
            position: 'absolute',
            bottom: 16,
            left: 16,
            zIndex: 10,
            background: 'rgba(6, 11, 23, 0.9)',
            backdropFilter: 'blur(10px)',
            border: '1px solid var(--border-color)',
            borderRadius: 8,
            padding: '10px 14px',
            fontSize: '0.72rem',
            display: 'flex',
            flexDirection: 'column',
            gap: 6,
          }}
        >
          <div style={{ fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Map Nodes & Trajectory Classification
          </div>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#0284c7', boxShadow: '0 0 6px #0284c7' }}></span> Live Current Location
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#ef4444' }}></span> Critical Exfil IP
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#f59e0b' }}></span> High Risk Sync
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#10b981' }}></span> Baseline SaaS
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
