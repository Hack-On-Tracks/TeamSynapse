import React, { useEffect } from 'react';
import { Play, Pause, RotateCcw, SkipBack, SkipForward, Clock, Zap } from 'lucide-react';

interface ReplayControllerProps {
  currentFrame: number;
  totalFrames: number;
  isPlaying: boolean;
  speed: number;
  currentTimestamp: string;
  onPlayToggle?: () => void;
  onPlay?: () => void;
  onPause?: () => void;
  onReset: () => void;
  onStepForward: () => void;
  onStepBackward: () => void;
  onSeek?: (frame: number) => void;
  onFrameSeek?: (frame: number) => void;
  onSpeedChange: (speed: number) => void;
  scenarios: string[];
  selectedScenario: string;
  onScenarioChange: (scenario: string) => void;
}

export const ReplayController: React.FC<ReplayControllerProps> = ({
  currentFrame,
  totalFrames,
  isPlaying,
  speed,
  currentTimestamp,
  onPlayToggle,
  onPlay,
  onPause,
  onReset,
  onStepForward,
  onStepBackward,
  onSeek,
  onFrameSeek,
  onSpeedChange,
  scenarios,
  selectedScenario,
  onScenarioChange,
}) => {
  const handleTogglePlay = () => {
    if (onPlayToggle) {
      onPlayToggle();
    } else if (isPlaying && onPause) {
      onPause();
    } else if (!isPlaying && onPlay) {
      onPlay();
    }
  };

  const handleSeek = (frame: number) => {
    if (onSeek) onSeek(frame);
    if (onFrameSeek) onFrameSeek(frame);
  };
  return (
    <div
      style={{
        background: 'var(--bg-secondary)',
        borderTop: '1px solid var(--border-color)',
        padding: '10px 20px',
        display: 'flex',
        alignItems: 'center',
        gap: 20,
        zIndex: 25,
      }}
    >
      {/* Control Buttons */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <button
          onClick={onReset}
          title="Reset to Day 1"
          style={{ background: 'var(--bg-card)', color: 'var(--text-secondary)', padding: 7, borderRadius: 6 }}
        >
          <RotateCcw size={15} />
        </button>
        <button
          onClick={onStepBackward}
          title="Step Backward"
          style={{ background: 'var(--bg-card)', color: 'var(--text-secondary)', padding: 7, borderRadius: 6 }}
        >
          <SkipBack size={15} />
        </button>
        <button
          onClick={handleTogglePlay}
          title={isPlaying ? 'Pause' : 'Play'}
          style={{
            background: isPlaying ? 'var(--accent-amber)' : 'var(--accent-cyan)',
            color: '#070d1e',
            padding: '7px 14px',
            borderRadius: 6,
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            fontWeight: 700,
            fontSize: '0.8rem',
          }}
        >
          {isPlaying ? <Pause size={15} /> : <Play size={15} />}
          {isPlaying ? 'PAUSE' : 'PLAY'}
        </button>
        <button
          onClick={onStepForward}
          title="Step Forward"
          style={{ background: 'var(--bg-card)', color: 'var(--text-secondary)', padding: 7, borderRadius: 6 }}
        >
          <SkipForward size={15} />
        </button>
      </div>

      {/* Speed Selector */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        <Zap size={14} style={{ color: 'var(--accent-cyan)' }} />
        <select
          value={speed}
          onChange={(e) => onSpeedChange(parseFloat(e.target.value))}
          style={{ height: 30, fontSize: '0.75rem', padding: '2px 8px' }}
        >
          <option value="0.5">0.5x</option>
          <option value="1">1.0x</option>
          <option value="2">2.0x</option>
          <option value="5">5.0x</option>
        </select>
      </div>

      {/* Scrubber Timeline Slider */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 4 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <Clock size={12} style={{ color: 'var(--accent-cyan)' }} />
            Simulation Frame: {currentFrame} / {Math.max(1, totalFrames)}
          </span>
          <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
            {currentTimestamp || 'Historical Window'}
          </span>
        </div>
        <input
          type="range"
          min="1"
          max={Math.max(1, totalFrames)}
          value={currentFrame}
          onChange={(e) => handleSeek(parseInt(e.target.value, 10))}
          style={{
            width: '100%',
            cursor: 'pointer',
            accentColor: 'var(--accent-cyan)',
            height: 4,
          }}
        />
      </div>

      {/* Scenario Filter */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Scenario:</span>
        <select
          value={selectedScenario}
          onChange={(e) => onScenarioChange(e.target.value)}
          style={{ height: 30, fontSize: '0.75rem', maxWidth: 180 }}
        >
          <option value="ALL">All Scenarios</option>
          {scenarios.map((s) => (
            <option key={s} value={s}>
              {s.replace(/_/g, ' ')}
            </option>
          ))}
        </select>
      </div>
    </div>
  );
};
