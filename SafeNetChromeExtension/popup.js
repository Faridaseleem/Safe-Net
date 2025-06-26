chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
  const currentUrl = tabs[0].url;
  fetch("https://localhost:5000/api/scan-url", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: currentUrl })
  })
    .then(res => res.json())
    .then(data => {
      document.getElementById("result").textContent = `Result: ${data.verdict}`;
    })
    .catch(err => {
      document.getElementById("result").textContent = "Error scanning URL.";
    });
});
