chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'checkUrl') {
      // Example: Forward API calls to VirusTotal
      sendResponse({ status: 'success' });
    }
  });