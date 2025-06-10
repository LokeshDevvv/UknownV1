// API endpoints to try
const API_ENDPOINTS = [
  'http://localhost:5000/api',
  'http://127.0.0.1:5000/api',
  'http://192.168.29.200:5000/api'
];

// Notification System
const NOTIFICATION_STYLES = `
  position: fixed !important;
  top: 20px !important;
  right: 20px !important;
  z-index: 2147483647 !important;
  padding: 16px !important;
  border-radius: 12px !important;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
  display: none !important;
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.25) !important;
  border: 2px solid #ff0055 !important;
  background: rgba(15, 15, 20, 0.98) !important;
  color: white !important;
  width: 320px !important;
  backdrop-filter: blur(10px) !important;
  min-height: 100px !important;
  pointer-events: auto !important;
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
  transform-origin: top right !important;
  opacity: 1 !important;
  visibility: visible !important;
`;

// Add styles for animations
const ANIMATION_STYLES = `
  @keyframes soteriaSlideIn {
    from { 
      transform: translateX(100%) scale(0.95); 
      opacity: 0; 
    }
    to { 
      transform: translateX(0) scale(1); 
      opacity: 1; 
    }
  }
  @keyframes soteriaSlideOut {
    from { 
      transform: translateX(0) scale(1); 
      opacity: 1; 
    }
    to { 
      transform: translateX(100%) scale(0.95); 
      opacity: 0; 
    }
  }
  #soteria-notification {
    animation: soteriaSlideIn 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  }
  #soteria-notification.hiding {
    animation: soteriaSlideOut 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  }
  #soteria-notification:hover {
    transform: translateY(-2px) scale(1.01) !important;
    box-shadow: 0 6px 28px rgba(0, 0, 0, 0.3) !important;
  }
`;

// Create notification container
const notification = document.createElement('div');
notification.id = 'soteria-notification';
notification.style.cssText = NOTIFICATION_STYLES;

// Add styles to document
const style = document.createElement('style');
style.textContent = ANIMATION_STYLES;
document.head.appendChild(style);

// Create container for notifications
const container = document.createElement('div');
container.id = 'soteria-container';
container.style.cssText = `
  position: fixed !important;
  top: 0 !important;
  right: 0 !important;
  z-index: 2147483647 !important;
  width: 360px !important;
  pointer-events: none !important;
`;
document.body.appendChild(container);
container.appendChild(notification);

let notificationTimeout;
let currentApiUrl = null;

async function testEndpoint(url) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout

  try {
    console.log(`Soteria: Testing endpoint ${url}/health`);
    const response = await fetch(`${url}/health`, {
      signal: controller.signal,
      mode: 'cors',
      headers: {
        'Accept': 'application/json'
      }
    });
    
    clearTimeout(timeoutId);
    
    if (response.ok) {
      const data = await response.json();
      console.log(`Soteria: Endpoint ${url} responded:`, data);
      return true;
    }
    return false;
  } catch (error) {
    clearTimeout(timeoutId);
    console.log(`Soteria: Endpoint ${url} failed:`, error.message);
    return false;
  }
}

async function findWorkingEndpoint() {
  for (const endpoint of API_ENDPOINTS) {
    if (await testEndpoint(endpoint)) {
      console.log(`Soteria: Found working endpoint: ${endpoint}`);
      return endpoint;
    }
  }
  return null;
}

async function analyzeUrl(url, apiEndpoint) {
  console.log(`Soteria: Analyzing URL ${url} using endpoint ${apiEndpoint}`);
  
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout

  try {
    const response = await fetch(`${apiEndpoint}/analyze`, {
      method: 'POST',
      signal: controller.signal,
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({ url })
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const result = await response.json();
    console.log('Soteria: Analysis result:', result);
    return result;
  } catch (error) {
    clearTimeout(timeoutId);
    throw error;
  }
}

// Simplified notification function that only shows high risk alerts
function showHighRiskAlert(result) {
  if (notificationTimeout) {
    clearTimeout(notificationTimeout);
  }

  // Only show notification for high risk
  if (result.risk_level?.toLowerCase() !== 'high risk') {
    return;
  }

  // Build notification content
  notification.innerHTML = `
    <div style="display: flex !important; flex-direction: column !important; gap: 12px !important;">
      <div style="display: flex !important; justify-content: space-between !important; align-items: center !important;">
        <strong style="color: #ff0055 !important; font-size: 16px !important;">⚠️ HIGH RISK DETECTED</strong>
        <span style="cursor: pointer !important; color: rgba(255,255,255,0.7) !important; padding: 4px !important; 
                     transition: all 0.2s ease-in-out !important;" 
              onmouseover="this.style.color='white'; this.style.transform='scale(1.1)'"
              onmouseout="this.style.color='rgba(255,255,255,0.7)'; this.style.transform='scale(1)'"
              onclick="this.parentElement.parentElement.parentElement.style.display='none'">✕</span>
      </div>
      <div style="font-size: 14px !important; color: rgba(255,255,255,0.9) !important; line-height: 1.5 !important;">
        🚨 This website has been flagged as potentially dangerous!
        ${result.features?.reasons ? `
          <div style="margin-top: 12px !important; padding: 8px !important; border-radius: 8px !important; 
                      background: rgba(255, 0, 85, 0.1) !important; font-size: 13px !important; 
                      color: rgba(255,255,255,0.8) !important;">
            ${result.features.reasons.join('<br>')}
          </div>
        ` : ''}
      </div>
    </div>
  `;

  // Show notification
  notification.style.removeProperty('display');
  notification.style.display = 'block !important';
  notification.style.visibility = 'visible !important';
  notification.style.opacity = '1 !important';

  // Auto-hide after 5 seconds
  notificationTimeout = setTimeout(() => {
    notification.classList.add('hiding');
    setTimeout(() => {
      notification.style.display = 'none';
      notification.classList.remove('hiding');
    }, 300);
  }, 5000);

  // Update extension icon
  chrome.runtime.sendMessage({
    type: 'updateIcon',
    riskLevel: result.risk_level
  });
}

// Main function to analyze the current page
async function analyzeCurrentPage() {
  try {
    chrome.runtime.sendMessage(
      { type: 'analyzeUrl', url: window.location.href },
      response => {
        if (response?.success && response.data) {
          showHighRiskAlert(response.data);
        }
      }
    );
  } catch (error) {
    console.error('Soteria: Error in analyzeCurrentPage:', error);
  }
}

// Start analysis immediately on page load
analyzeCurrentPage();

// Listen for navigation events
let lastUrl = window.location.href;
new MutationObserver(() => {
  const currentUrl = window.location.href;
  if (currentUrl !== lastUrl) {
    lastUrl = currentUrl;
    analyzeCurrentPage();
  }
}).observe(document.body, { subtree: true, childList: true }); 