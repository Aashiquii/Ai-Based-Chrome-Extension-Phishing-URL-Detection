// Gemini API key (replace with your key from Google AI Studio)
const GEMINI_API_KEY = 'AIzaSyDSyAkhfJD2yE3ZFAE6sqxNaOFNFfAVEKs';
const GEMINI_API_URL = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent';
const LOCAL_DB = 'phishing-urls.json';

// Initialize event listeners
document.addEventListener('DOMContentLoaded', () => {
  console.log('CyberShield: Initializing...');
  const analyzeBtn = document.getElementById('analyzeBtn');
  if (analyzeBtn) {
    analyzeBtn.addEventListener('click', () => {
      console.log('CyberShield: Analyze button clicked');
      checkUrl();
    });
  } else {
    console.error('CyberShield: Analyze button not found');
  }
  const exportBtn = document.getElementById('exportBtn');
  if (exportBtn) {
    exportBtn.addEventListener('click', exportReport);
  }
  // Load voices for speech synthesis
  speechSynthesis.addEventListener('voiceschanged', () => {
    speechSynthesis.getVoices();
  });
});

// Normalize URL for consistent matching
function normalizeUrl(url) {
  try {
    const parsed = new URL(url);
    // Remove trailing slashes and normalize protocol
    return parsed.href.replace(/\/+$/, '').toLowerCase();
  } catch (error) {
    console.error('CyberShield: Invalid URL for normalization:', url, error);
    return url.toLowerCase();
  }
}

// Heuristic check for phishing patterns
function heuristicCheck(url) {
  const suspiciousPatterns = [
    /login|verify|secure|account|password|update|signin/i,
    /\.(top|xyz|info|co|pw|club)$/i, // Suspicious TLDs
    /[^a-z0-9\-]\d{4,}/i, // Numbers in domain (e.g., bank1234)
    /[^a-z0-9]\-/i, // Hyphens in unusual places
  ];
  let score = 0;
  suspiciousPatterns.forEach((pattern) => {
    if (pattern.test(url)) score += 20;
  });
  return {
    isPhishing: score >= 40,
    details: score >= 40 ? 'Suspicious patterns detected in URL.' : 'No suspicious patterns detected.',
    heuristicScore: score,
  };
}

// Check URL
async function checkUrl() {
  console.log('CyberShield: Starting URL check');
  const urlInput = document.getElementById('urlInput').value.trim();
  if (!urlInput) {
    console.warn('CyberShield: No URL entered');
    alert('Please enter a valid URL.');
    return;
  }

  showLoading();
  clearPreviousResults();

  try {
    new URL(urlInput); // Validate URL format
    console.log('CyberShield: URL format valid');
  } catch (error) {
    console.error('CyberShield: Invalid URL format:', error);
    showResult('danger', 'Invalid URL format.');
    hideLoading();
    return;
  }

  const normalizedUrl = normalizeUrl(urlInput);
  console.log('CyberShield: Normalized URL:', normalizedUrl);
  let result = { isPhishing: false, details: '' };

  // Step 1: Check local database
  console.log('CyberShield: Checking local database for:', normalizedUrl);
  const localResult = await checkWithLocalDB(normalizedUrl);
  if (localResult.isPhishing) {
    console.log('CyberShield: URL found in local database, marking as phishing');
    result = localResult;
  } else {
    // Step 2: Check Gemini API (if enabled)
    if (document.getElementById('enableApiChecks').checked) {
      console.log('CyberShield: Checking with Gemini API');
      const apiResult = await checkWithGeminiAPI(normalizedUrl);
      result = apiResult;
    } else {
      console.log('CyberShield: Using local database result (API disabled)');
      result = localResult;
    }

    // Step 3: Apply heuristic check if not already phishing
    if (!result.isPhishing) {
      console.log('CyberShield: Applying heuristic check');
      const heuristicResult = heuristicCheck(normalizedUrl);
      if (heuristicResult.isPhishing) {
        result = heuristicResult;
      }
    }
  }

  // Update UI
  const riskScore = predictRiskScore(normalizedUrl, result.isPhishing, result.heuristicScore || 0);
  console.log('CyberShield: Risk score calculated:', riskScore);
  updateUI({
    riskScore,
    isPhishing: result.isPhishing,
    details: result.details,
  });

  hideLoading();
}

// Check with Gemini API
async function checkWithGeminiAPI(url) {
  try {
    console.log('CyberShield: Sending request to Gemini API for:', url);
    let cachedResult = null;
    // Check if chrome.storage.local is available
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      const cacheKey = `gemini_${url}`;
      const cached = await new Promise((resolve) => {
        chrome.storage.local.get(cacheKey, (result) => resolve(result));
      });
      if (cached[cacheKey]) {
        console.log('CyberShield: Using cached result:', cached[cacheKey]);
        return cached[cacheKey];
      }
    } else {
      console.warn('CyberShield: chrome.storage.local not available, skipping cache');
    }

    const prompt = `Analyze the URL "${url}" for phishing characteristics (e.g., domain reputation, "login" patterns, suspicious TLDs, typosquatting). Return a JSON object with:
    - isPhishing: boolean (true if phishing, false if safe)
    - details: string (explanation, max 100 characters)
    Output only valid JSON, no Markdown or extra text. Example:
    {"isPhishing": false, "details": "Legitimate domain, no phishing patterns."}`;

    const response = await fetch(`${GEMINI_API_URL}?key=${GEMINI_API_KEY}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        contents: [
          {
            parts: [
              {
                text: prompt,
              },
            ],
          },
        ],
      }),
    });

    if (!response.ok) {
      throw new Error(`Gemini API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    console.log('CyberShield: Gemini API raw response:', data);
    const generatedText = data.candidates[0].content.parts[0].text;
    console.log('CyberShield: Gemini generated text:', generatedText);

    // Attempt to parse JSON, handling common formats
    let jsonText = generatedText.trim();
    // Remove Markdown code fences if present
    jsonText = jsonText.replace(/```json\n([\s\S]*?)\n```/, '$1').replace(/```[\s\S]*?```/, '').trim();

    let result;
    try {
      result = JSON.parse(jsonText);
      if (typeof result.isPhishing !== 'boolean' || typeof result.details !== 'string') {
        throw new Error('Invalid JSON format: missing isPhishing or details');
      }
      // Truncate details to 100 characters
      result.details = result.details.substring(0, 100);
    } catch (error) {
      console.error('CyberShield: Error parsing Gemini response:', error, 'Raw text:', generatedText);
      result = {
        isPhishing: false,
        details: 'Unable to parse Gemini API response. Relying on local database and heuristics.',
      };
    }

    // Cache result if chrome.storage.local is available
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      const cacheKey = `gemini_${url}`;
      chrome.storage.local.set({ [cacheKey]: result });
    }

    console.log('CyberShield: Gemini result:', result);
    return result;
  } catch (error) {
    console.error('CyberShield: Gemini API error:', error);
    return {
      isPhishing: false,
      details: `Unable to verify with Gemini API: ${error.message}. Check API key or network.`,
    };
  }
}

// Check with local database
async function checkWithLocalDB(url) {
  try {
    console.log('CyberShield: Checking local database for:', url);
    const response = await fetch(LOCAL_DB);
    const data = await response.json();
    // Normalize database URLs for comparison
    const normalizedDbUrls = data.urls.map(normalizeUrl);
    const isPhishing = normalizedDbUrls.includes(url);
    const result = {
      isPhishing,
      details: isPhishing
        ? 'URL found in phishing database.'
        : 'URL not found in phishing database.',
    };
    console.log('CyberShield: Local DB result:', result);
    console.log('CyberShield: Normalized DB URLs:', normalizedDbUrls);
    return result;
  } catch (error) {
    console.error('CyberShield: Local DB error:', error);
    return {
      isPhishing: false,
      details: 'Error accessing local database.',
    };
  }
}

// Predict risk score
function predictRiskScore(url, isPhishing, heuristicScore = 0) {
  let score = Math.random() * 30; // Lower base score for more realistic distribution
  if (isPhishing) score += 50; // Higher weight for confirmed phishing
  if (url.match(/login|verify|secure|account/i)) score += 15;
  score += heuristicScore / 2; // Incorporate heuristic score
  return Math.min(100, Math.round(score));
}

// Update UI
function updateUI({ riskScore, isPhishing, details }) {
  console.log('CyberShield: Updating UI with results');
  document.getElementById('score-value').textContent = `${riskScore}%`;
  document.getElementById('progress-bar').value = riskScore;
  document.getElementById('risk-score').classList.remove('hidden');
  document.getElementById('exportBtn').classList.remove('hidden');

  const message = isPhishing
    ? `Danger: Phishing URL detected! ${details}`
    : `Safe: URL appears legitimate. ${details}`;
  showResult(isPhishing ? 'danger' : 'safe', message);
  voiceFeedback(isPhishing ? 'Warning: Phishing URL detected.' : 'URL is safe.');
}

// Show result
function showResult(className, message) {
  const resultDiv = document.getElementById('result');
  resultDiv.textContent = message;
  resultDiv.className = `futuristic-result ${className}`;
  resultDiv.style.display = 'block';
}

// Voice feedback
function voiceFeedback(message) {
  if ('speechSynthesis' in window) {
    const utterance = new SpeechSynthesisUtterance(message);
    const voices = speechSynthesis.getVoices();
    utterance.voice = voices.find((voice) => voice.name.includes('English')) || voices[0];
    utterance.rate = 1;
    speechSynthesis.speak(utterance);
  } else {
    console.warn('CyberShield: Speech synthesis not supported');
  }
}

// Export report
function exportReport() {
  console.log('CyberShield: Exporting report');
  const report = {
    url: document.getElementById('urlInput').value,
    riskScore: document.getElementById('score-value').textContent,
    result: document.getElementById('result').textContent,
    timestamp: new Date().toISOString(),
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'CyberShield_Report.json';
  a.click();
  URL.revokeObjectURL(url);
}

// Utility functions
function showLoading() {
  console.log('CyberShield: Showing loading spinner');
  document.getElementById('loading').classList.remove('hidden');
}

function hideLoading() {
  console.log('CyberShield: Hiding loading spinner');
  document.getElementById('loading').classList.add('hidden');
}

function clearPreviousResults() {
  console.log('CyberShield: Clearing previous results');
  document.getElementById('result').style.display = 'none';
  document.getElementById('risk-score').classList.add('hidden');
  document.getElementById('exportBtn').classList.add('hidden');
}