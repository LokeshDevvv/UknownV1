// Initialize extension when installed
chrome.runtime.onInstalled.addListener(() => {
  console.log('Soteria Background: Extension installed');
  
  // Create context menu item
  try {
    chrome.contextMenus.create({
      id: 'analyzeLinkWithSoteria',
      title: 'Analyze with Soteria',
      contexts: ['link']
    });
    console.log('Soteria Background: Context menu created');
  } catch (error) {
    console.error('Soteria Background: Error creating context menu:', error);
  }
});

// API endpoints to try
const API_ENDPOINTS = [
  'http://localhost:5000/api',
  'http://127.0.0.1:5000/api',
  'http://192.168.29.200:5000/api'
];

let currentApiUrl = null;

async function testEndpoint(url) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    console.log(`Soteria Background: Testing endpoint ${url}/health`);
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
      console.log(`Soteria Background: Endpoint ${url} responded:`, data);
      return true;
    }
    console.log(`Soteria Background: Endpoint ${url} returned status:`, response.status);
    return false;
  } catch (error) {
    clearTimeout(timeoutId);
    console.log(`Soteria Background: Endpoint ${url} failed:`, error.message);
    return false;
  }
}

async function findWorkingEndpoint() {
  for (const endpoint of API_ENDPOINTS) {
    if (await testEndpoint(endpoint)) {
      console.log(`Soteria Background: Found working endpoint: ${endpoint}`);
      return endpoint;
    }
  }
  return null;
}

async function analyzeUrl(url, apiEndpoint) {
  console.log('Soteria Background: Analyzing URL:', url, 'with endpoint:', apiEndpoint);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);

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
    console.log('Soteria Background: Got response:', response.status);

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const result = await response.json();
    console.log('Soteria Background: Analysis result:', result);
    return result;
  } catch (error) {
    clearTimeout(timeoutId);
    console.error('Soteria Background: Analysis error:', error, 'Stack:', error.stack);
    throw error;
  }
}

async function handleAnalysis(url) {
  console.log('Soteria Background: Starting analysis for URL:', url);
  
  // Find a working API endpoint if we don't have one
  if (!currentApiUrl) {
    console.log('Soteria Background: Finding working endpoint...');
    currentApiUrl = await findWorkingEndpoint();
    if (!currentApiUrl) {
      console.error('Soteria Background: No working endpoint found');
      throw new Error('No working API endpoint found');
    }
    console.log('Soteria Background: Using endpoint:', currentApiUrl);
  }

  // Analyze the URL
  try {
    const result = await analyzeUrl(url, currentApiUrl);
    console.log('Soteria Background: Analysis completed:', result);
    return result;
  } catch (error) {
    console.error('Soteria Background: Analysis error:', error);
    currentApiUrl = null; // Reset the API URL so we'll try finding a working endpoint next time
    throw error;
  }
}

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  console.log('Soteria Background: Context menu clicked', info);
  if (info.menuItemId === 'analyzeLinkWithSoteria' && info.linkUrl) {
    handleAnalysis(info.linkUrl)
      .then(result => {
        // Send result to content script
        chrome.tabs.sendMessage(tab.id, {
          type: 'analysisResult',
          data: result
        });
      })
      .catch(error => {
        console.error('Soteria Background: Analysis failed:', error);
        chrome.tabs.sendMessage(tab.id, {
          type: 'analysisError',
          error: error.message
        });
      });
  }
});

// Listen for messages from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Soteria Background: Received message:', request, 'from:', sender);
  
  if (request.type === 'analyzeUrl') {
    console.log('Soteria Background: Processing analyzeUrl request for:', request.url);
    handleAnalysis(request.url)
      .then(result => {
        console.log('Soteria Background: Analysis successful:', result);
        sendResponse({ success: true, data: result });
      })
      .catch(error => {
        console.error('Soteria Background: Analysis failed:', error, 'Stack:', error.stack);
        sendResponse({ success: false, error: error.message });
      });
    return true; // Will respond asynchronously
  }

  if (request.type === 'updateIcon') {
    console.log('Soteria Background: Updating icon for risk level:', request.riskLevel);
    updateIcon(request.riskLevel);
  }
});

// Update extension icon based on risk level
function updateIcon(riskLevel) {
  let color;
  switch (riskLevel?.toLowerCase()) {
    case 'high risk':
      color = '#ff0055';
      break;
    case 'moderate risk':
      color = '#ffcc00';
      break;
    case 'low risk':
      color = '#00ff66';
      break;
    default:
      color = '#808080';
  }
  
  // Create canvas for dynamic icon
  const canvas = new OffscreenCanvas(16, 16);
  const ctx = canvas.getContext('2d');
  
  // Draw shield shape
  ctx.beginPath();
  ctx.moveTo(8, 2);
  ctx.lineTo(14, 4);
  ctx.lineTo(14, 8);
  ctx.quadraticCurveTo(14, 12, 8, 14);
  ctx.quadraticCurveTo(2, 12, 2, 8);
  ctx.lineTo(2, 4);
  ctx.closePath();
  
  // Fill with risk level color
  ctx.fillStyle = color;
  ctx.fill();
  
  // Add border
  ctx.strokeStyle = '#ffffff';
  ctx.lineWidth = 1;
  ctx.stroke();
  
  // Update the extension icon
  chrome.action.setIcon({
    imageData: ctx.getImageData(0, 0, 16, 16)
  });
}

// Handle tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // Reset icon to default when page loads
    updateIcon('default');
  }
}); 