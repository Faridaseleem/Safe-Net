import React from 'react';
import { useUser } from '../contexts/UserContext';
import './ScanCounter.css';

const ScanCounter = () => {
  const { user, scanCount } = useUser();

  // Don't show counter for premium/admin users or if scan count is not loaded
  if (!user || !scanCount || user.role === 'premium' || user.role === 'admin') {
    return null;
  }

  // Don't show if user has unlimited scans
  if (scanCount.remainingScans === -1) {
    return null;
  }

  const { remainingScans, totalScans, dailyLimit } = scanCount;
  
  // Calculate percentage for progress bar
  const percentageUsed = (totalScans / dailyLimit) * 100;
  const percentageRemaining = 100 - percentageUsed;

  // Determine color based on remaining scans
  const getProgressColor = () => {
    if (remainingScans === 0) return '#ff4757'; // Red when no scans left
    if (remainingScans <= 2) return '#ffa502'; // Orange when 1-2 scans left
    if (remainingScans <= 5) return '#ffb142'; // Yellow when 3-5 scans left
    return '#2ed573'; // Green when 6+ scans left
  };

  return (
    <div className="scan-counter">
      <div className="scan-counter-header">
        <span className="scan-counter-icon">🔍</span>
        <span className="scan-counter-title">Daily Scan Limit</span>
      </div>
      
      <div className="scan-counter-content">
        <div className="scan-counter-stats">
          <div className="scan-counter-stat">
            <span className="stat-label">Remaining:</span>
            <span className={`stat-value ${remainingScans === 0 ? 'no-scans-left' : ''}`}>
              {remainingScans} / {dailyLimit}
            </span>
          </div>
          
          <div className="scan-counter-stat">
            <span className="stat-label">Used today:</span>
            <span className="stat-value">{totalScans}</span>
          </div>
        </div>

        <div className="scan-counter-progress">
          <div className="progress-bar">
            <div 
              className="progress-fill"
              style={{ 
                width: `${percentageRemaining}%`,
                backgroundColor: getProgressColor()
              }}
            ></div>
          </div>
        </div>

        {remainingScans === 0 && (
          <div className="scan-counter-warning">
            <span className="warning-icon">⚠️</span>
            <span className="warning-text">
              Daily limit reached. Upgrade to Premium for unlimited scans!
            </span>
          </div>
        )}

        {remainingScans > 0 && remainingScans <= 3 && (
          <div className="scan-counter-info">
            <span className="info-icon">💡</span>
            <span className="info-text">
              Only {remainingScans} scan{remainingScans !== 1 ? 's' : ''} left today
            </span>
          </div>
        )}
      </div>
    </div>
  );
};

export default ScanCounter; 