chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "scan-url",
    title: "Scan with SafeNet",
    contexts: ["link"]
  });
});

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId === "scan-url") {
    chrome.tabs.create({
      url: `https://localhost:5000/scan-result?url=${encodeURIComponent(info.linkUrl)}`
    });
  }
});
