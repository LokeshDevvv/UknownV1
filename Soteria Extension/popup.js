const API_URL = 'http://localhost:5000/api';

// UI Elements
const loadingDiv = document.getElementById('loading');
const contentDiv = document.getElementById('content');
const resultDiv = document.getElementById('result');
const scoreDiv = document.getElementById('score');
const threatsList = document.getElementById('threats');
const apiStatus = document.getElementById('apiStatus');
const apiStatusText = document.getElementById('apiStatusText');
const urlDisplay = document.getElementById('urlDisplay');
const urlDetails = document.getElementById('urlDetails');
const securityScore = document.getElementById('securityScore');
const riskLevel = document.getElementById('riskLevel');

// Check API connection on popup open
checkApiConnection();

async function checkApiConnection() {
  try {
    const response = await fetch(`${API_URL}/health`);
    if (response.ok) {
      apiStatus.classList.add('connected');
      apiStatusText.textContent = 'API CONNECTED';
      apiStatusText.classList.add('text-cyber-green');
      return true;
    } else {
      throw new Error('API not responding');
    }
  } catch (err) {
    apiStatus.classList.remove('connected');
    apiStatusText.textContent = 'API DISCONNECTED';
    apiStatusText.classList.remove('text-cyber-green');
    return false;
  }
}

function parseURL(url) {
  try {
    const urlObj = new URL(url);
    return {
      protocol: urlObj.protocol,
      hostname: urlObj.hostname,
      pathname: urlObj.pathname,
      searchParams: urlObj.search,
      port: urlObj.port || (urlObj.protocol === 'https:' ? '443' : '80')
    };
  } catch (err) {
    return null;
  }
}

function showLoading() {
  loadingDiv.style.display = 'flex';
  resultDiv.style.display = 'none';
}

function hideLoading() {
  loadingDiv.style.display = 'none';
  resultDiv.style.display = 'block';
}

async function analyzeURL(url) {
  if (!url) return;

  // Show loading state
  showLoading();

  try {
    const isConnected = await checkApiConnection();
    if (!isConnected) {
      throw new Error('API is not connected');
    }

    const response = await fetch(`${API_URL}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      throw new Error('Failed to analyze URL');
    }

    const result = await response.json();
    displayResult(result, url);
  } catch (err) {
    displayError(err.message, url);
  }
}

function displayResult(result, url) {
  // Display URL and its details
  urlDisplay.textContent = result.url;

  // Use API response fields for details
  urlDetails.innerHTML = `
    <div class="url-detail-item">
      <div class="label">Domain</div>
      <div class="value">${result.domain}</div>
    </div>
  `;

  // Clear previous results
  threatsList.innerHTML = '';

  // Calculate threat score (0-100)
  const threatScore = Math.min(Math.round(result.total_score * 100), 100);
  let scoreClass = 'high';
  let riskText = result.risk_level || 'Unknown';

  if (result.risk_level === 'Low Risk') {
    scoreClass = 'safe';
  } else if (result.risk_level === 'Medium Risk') {
    scoreClass = 'moderate';
  }

  // Update security metrics
  updateScore(threatScore);
  updateRiskLevel(result.risk_level);

  // Calculate security score (inverse of threat score)
  const securityScoreValue = 100 - threatScore;
  securityScore.textContent = `${securityScoreValue}%`;

  // Add main message and key security info
  if (result.features) {
    // Show main message (safe/unsafe)
    if (result.features.main_message) {
      const mainMsg = document.createElement('div');
      mainMsg.className = 'main-message';
      mainMsg.textContent = result.features.main_message;
      threatsList.appendChild(mainMsg);
    }
    // Show SSL certificate status and any other key security info
    if (result.features.reasons) {
      // Only show SSL and other security info, not all reasons
      result.features.reasons.forEach(reason => {
        if (reason.toLowerCase().includes('ssl') || reason.toLowerCase().includes('https') || reason.toLowerCase().includes('secure')) {
          const li = document.createElement('li');
          li.className = 'threat-item';
          li.textContent = reason;
          threatsList.appendChild(li);
        }
      });
    }
    // If not safe, show a clear warning
    if (result.risk_level !== 'Low Risk') {
      const warning = document.createElement('div');
      warning.className = 'main-message';
      warning.style.color = '#ff0055';
      warning.textContent = '⚠️ This link is NOT SAFE!';
      threatsList.appendChild(warning);
    }
  }

  // Show results
  hideLoading();
}

function displayError(message, url) {
  loadingDiv.style.display = 'none';
    contentDiv.innerHTML = `
      <div class="url">${url}</div>
    <div class="error">❌ ${message}</div>
      <button id="retryButton">🔄 Retry Analysis</button>
    `;

    // Add retry functionality
    document.getElementById('retryButton')?.addEventListener('click', () => {
    analyzeURL(url);
  });
}

function updateApiStatus(connected) {
  const statusIndicator = document.getElementById('apiStatus');
  const statusText = document.getElementById('apiStatusText');
  
  if (connected) {
    statusIndicator.classList.add('connected');
    statusText.textContent = 'API CONNECTED';
    statusText.classList.add('text-cyber-green');
  } else {
    statusIndicator.classList.remove('connected');
    statusText.textContent = 'API DISCONNECTED';
    statusText.classList.remove('text-cyber-green');
  }
}

function updateScore(score) {
  const scoreElement = document.getElementById('score');
  scoreElement.textContent = `${score}/100`;
  
  // Update score color based on value
  scoreElement.classList.remove('safe', 'moderate', 'high');
  if (score >= 70) {
    scoreElement.classList.add('safe');
  } else if (score >= 40) {
    scoreElement.classList.add('moderate');
  } else {
    scoreElement.classList.add('high');
  }
}

function updateRiskLevel(level) {
  const riskElement = document.getElementById('riskLevel');
  riskElement.textContent = level.toUpperCase();
  
  // Update risk level color
  riskElement.classList.remove('text-cyber-green', 'text-cyber-yellow', 'text-cyber-red');
  switch (level.toLowerCase()) {
    case 'safe':
      riskElement.classList.add('text-cyber-green');
      break;
    case 'moderate':
      riskElement.classList.add('text-cyber-yellow');
      break;
    case 'high':
      riskElement.classList.add('text-cyber-red');
      break;
  }
}

function updateThreats(threats) {
  const threatsList = document.getElementById('threats');
  threatsList.innerHTML = '';
  
  threats.forEach(threat => {
    const li = document.createElement('li');
    const icon = document.createElement('i');
    icon.setAttribute('data-lucide', 'alert-triangle');
    icon.classList.add('text-cyber-yellow');
    
    li.appendChild(icon);
    li.appendChild(document.createTextNode(threat));
    threatsList.appendChild(li);
  });
  
  // Update icons
  lucide.createIcons();
}

// Analyze current tab's URL when popup opens
document.addEventListener('DOMContentLoaded', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    const url = tabs[0].url;
    
    // First, try to get stored analysis from background script
    chrome.runtime.sendMessage({ type: 'getStoredAnalysis' }, response => {
      if (response && response.success && response.data && response.data.url === url) {
        console.log('Soteria Popup: Displaying stored analysis.');
        displayResult(response.data.data, response.data.url); // Use response.data.data for the actual result
      } else {
        console.log('Soteria Popup: No stored analysis or URL mismatch, initiating new analysis.');
    analyzeURL(url);
      }
    });
    });
}); 