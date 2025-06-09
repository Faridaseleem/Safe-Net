// src/components/Chatbot.js
import React, { useState } from "react";
import axios from "axios";
import "./Chatbot.css";
import chatbotIcon from "./chatbot.png"; // Ensure chatbot.png is in the same folder or adjust the path

const Chatbot = () => {
  // General chatbot states.
  const [isOpen, setIsOpen] = useState(false);
  // chatMode controls which main view is shown:
  // "main" shows the two main buttons,
  // "services" shows the service selection and input,
  // "askai" shows the Ask AI interface.
  const [chatMode, setChatMode] = useState("main");
  const [selectedService, setSelectedService] = useState(null);
  const [userText, setUserText] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);
  const [result, setResult] = useState(null);

  // Toggle the chatbot window open/close.
  const toggleChatbot = () => {
    setIsOpen((prev) => !prev);
    if (!isOpen) {
      // If opening, reset to main menu and clear all inputs.
      setChatMode("main");
      setSelectedService(null);
      setUserText("");
      setSelectedFile(null);
      setResult(null);
    }
  };

  // These are the services available in the "services" mode.
  const services = [
    { name: "Scan URL", type: "scan_url" },
    { name: "Scan Email", type: "scan_email" },
    { name: "Report URL", type: "report_url" },
    { name: "Education", type: "education" }
  ];

  // When a service is selected from the services mode, clear previous data.
  const handleServiceSelection = (service) => {
    console.log("Service selected:", service.type);
    setSelectedService(service);
    setResult(null);
    setUserText("");
    setSelectedFile(null);
  };

  // The submit handler now distinguishes between Ask AI and Services.
  const handleSubmit = () => {
    if (chatMode === "askai") {
      // In Ask AI mode, userText contains the question.
      if (!userText) return;
      console.log("Submitting Ask AI request:", userText);
      axios
        .post(
          "http://localhost:5000/api/ask-ai",
          { question: userText },
          { withCredentials: true }
        )
        .then((res) => {
          console.log("Response from ask-ai:", res.data);
          setResult(res.data);
        })
        .catch((err) => {
          console.error("Failed to get AI answer:", err);
          setResult({ error: "Failed to get answer from AI." });
        });
    } else if (chatMode === "services") {
      if (!selectedService) return;
      console.log("Submitting service call for:", selectedService.type);
      console.log("User input:", userText, "Selected File:", selectedFile);
      if (selectedService.type === "scan_url") {
        axios
          .post(
            "http://localhost:5000/api/scan-url",
            { url: userText },
            { withCredentials: true }
          )
          .then((res) => {
            console.log("Response from scan_url:", res.data);
            setResult(res.data);
          })
          .catch((err) => {
            console.error(err);
            setResult({ error: "Failed to scan URL." });
          });
      } else if (selectedService.type === "report_url") {
        axios
          .post(
            "http://localhost:5000/api/report-url",
            { url: userText },
            { withCredentials: true }
          )
          .then((res) => {
            console.log("Response from report_url:", res.data);
            setResult(res.data);
          })
          .catch((err) => {
            console.error(err);
            setResult({ error: "Failed to report URL." });
          });
      } else if (selectedService.type === "scan_email") {
        if (!selectedFile) {
          setResult({ error: "Please upload a .eml file." });
          return;
        }
        const formData = new FormData();
        // IMPORTANT: Use "emlFile" as the key so that it matches your working Scan Email service.
        formData.append("emlFile", selectedFile);
        console.log("FormData prepared with file:", selectedFile.name);
        axios
          .post("http://localhost:5000/api/scan-eml-file", formData, {
            withCredentials: true
            // Let the browser automatically set the Content-Type header.
          })
          .then((res) => {
            console.log("Response from scan-eml-file:", res.data);
            setResult(res.data);
          })
          .catch((err) => {
            console.error("Error in scan_eml_file axios call:", err);
            setResult({ error: "Failed to scan email." });
          });
      } else if (selectedService.type === "education") {
        axios
          .get("http://localhost:5000/api/education/phishing", {
            withCredentials: true
          })
          .then((res) => {
            console.log("Response from education:", res.data);
            setResult(res.data);
          })
          .catch((err) => {
            console.error(err);
            setResult({ error: "Failed to load education content." });
          });
      }
    }
  };

  // Allow submission via pressing Enter in text inputs.
  const handleTextKeyDown = (e) => {
    if (e.key === "Enter") handleSubmit();
  };

  // Render the main menu with two buttons: "Choose from our services." and "Ask AI".
  const renderMainMenu = () => {
    return (
      <div className="chatbot-main-menu">
        <button
          className="main-menu-button"
          onClick={() => setChatMode("services")}
        >
          Choose from our services.
        </button>
        <button
          className="main-menu-button"
          onClick={() => setChatMode("askai")}
        >
          Ask AI
        </button>
      </div>
    );
  };

  // Render the Ask AI interface.
  const renderAskAIMode = () => {
    return (
      <div className="ask-ai-container">
        <h4>Ask AI</h4>
        <input
          type="text"
          value={userText}
          placeholder="Enter your question"
          onChange={(e) => setUserText(e.target.value)}
          onKeyDown={handleTextKeyDown}
          className="ask-ai-input"
        />
        <button onClick={handleSubmit} className="submit-button">
          Ask
        </button>
        <button
          className="back-button"
          onClick={() => {
            setChatMode("main");
            setResult(null);
            setUserText("");
          }}
        >
          Back
        </button>
      </div>
    );
  };

  // Render the service selection UI.
  const renderServiceSelection = () => {
    return (
      <div className="service-selection">
        <h4>Choose a Service:</h4>
        {services.map((service, index) => (
          <button
            key={index}
            className="service-button"
            onClick={() => handleServiceSelection(service)}
          >
            {service.name}
          </button>
        ))}
        <button
          className="back-button"
          onClick={() => setChatMode("main")}
        >
          Back
        </button>
      </div>
    );
  };

  // Render the service input UI if a particular service is selected.
  const renderServiceInput = () => {
    if (!selectedService) return null;
    let inputComponent = null;
    if (
      selectedService.type === "scan_url" ||
      selectedService.type === "report_url"
    ) {
      inputComponent = (
        <input
          type="text"
          value={userText}
          placeholder={
            selectedService.type === "scan_url"
              ? "Enter URL to scan"
              : "Enter URL to report"
          }
          onChange={(e) => setUserText(e.target.value)}
          onKeyDown={handleTextKeyDown}
          className="service-input"
        />
      );
    } else if (selectedService.type === "scan_email") {
      inputComponent = (
        <input
          type="file"
          accept=".eml"
          onChange={(e) => {
            console.log("File selected:", e.target.files[0]);
            setSelectedFile(e.target.files[0]);
          }}
          className="service-input"
        />
      );
    } else if (selectedService.type === "education") {
      inputComponent = <p>No input required. Press Submit to view content.</p>;
    }
    return (
      <div className="service-input-container">
        <p>Selected: {selectedService.name}</p>
        {inputComponent}
        <button onClick={handleSubmit} className="submit-button">
          Submit
        </button>
        <button
          className="back-button"
          onClick={() => {
            setSelectedService(null);
            setUserText("");
            setSelectedFile(null);
            setResult(null);
          }}
        >
          Back
        </button>
      </div>
    );
  };

  // Render the result area in a scrollable container.
  let resultContent = null;
  if (result) {
    let reportText = "";
    if (
      selectedService &&
      (selectedService.type === "scan_url" ||
        selectedService.type === "report_url")
    ) {
      reportText = result.scan_report
        ? result.scan_report
        : JSON.stringify(result, null, 2);
    } else if (selectedService && selectedService.type === "scan_email") {
      const resultCopy = { ...result };
      delete resultCopy.emailBody; // Do not show emailBody
      reportText = JSON.stringify(resultCopy, null, 2);
    } else if (selectedService && selectedService.type === "education") {
      reportText = JSON.stringify(result, null, 2);
    } else if (chatMode === "askai") {
      reportText = JSON.stringify(result, null, 2);
    } else {
      reportText = JSON.stringify(result, null, 2);
    }
    resultContent = (
      <div className="result-area">
        <pre
          style={{
            overflowY: "auto",
            maxHeight: "250px",
            backgroundColor: "#111",
            color: "#eee",
            padding: "10px",
            borderRadius: "4px",
            fontSize: "0.9em"
          }}
        >
          {reportText}
        </pre>
      </div>
    );
  }

  // Compose final content based on chatMode.
  let chatbotContent;
  if (chatMode === "main") {
    chatbotContent = renderMainMenu();
  } else if (chatMode === "askai") {
    chatbotContent = renderAskAIMode();
  } else if (chatMode === "services") {
    chatbotContent = !selectedService
      ? renderServiceSelection()
      : renderServiceInput();
  }
  if (resultContent) {
    chatbotContent = (
      <div>
        {chatbotContent}
        {resultContent}
      </div>
    );
  }

  // Chatbot window with a header that displays the chatbot logo centered.
  const chatbotWindow = isOpen ? (
    <div className="chatbot-window">
      <div className="chatbot-header">
        <img
          src={chatbotIcon}
          alt="Chatbot Logo"
          className="chatbot-logo"
        />
      </div>
      {chatbotContent}
    </div>
  ) : null;

  // The toggle button remains at its location; it displays the chatbot icon.
  const toggleButton = (
    <button className="chatbot-toggle" onClick={toggleChatbot}>
      <img src={chatbotIcon} alt="Chatbot" className="chatbot-icon" />
    </button>
  );

  return (
    <div className="chatbot-container">
      {chatbotWindow}
      {toggleButton}
    </div>
  );
};

export default Chatbot;
