import React, { useState, useEffect, useRef } from "react";
import axios from "axios";
import "./Chatbot.css";
import chatbotIcon from "./chatbot.png";
import telegramIcon from "./telegram.png"; // Add this import
import { useUser } from "../contexts/UserContext";

const Chatbot = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [chatMode, setChatMode] = useState("main");
  const [selectedService, setSelectedService] = useState(null);
  const [userText, setUserText] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);
  const [result, setResult] = useState(null);
  const [chatMessages, setChatMessages] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const chatContainerRef = useRef(null);
  const [telegramLink, setTelegramLink] = useState("");
  const chatbotRef = useRef(null);
  const [position, setPosition] = useState({ x: 60, y: 120 });
  const [dragging, setDragging] = useState(false);
  const [rel, setRel] = useState({ x: 0, y: 0 });

  const { user } = useUser();

  console.log("Current user in Chatbot:", user);

  const onMouseDown = (e) => {
    if (e.button !== 0) return;
    const rect = chatbotRef.current.getBoundingClientRect();
    setDragging(true);
    setRel({
      x: e.pageX - rect.left,
      y: e.pageY - rect.top
    });
    e.stopPropagation();
    e.preventDefault();
  };

  const onMouseMove = (e) => {
    if (!dragging) return;
    setPosition({
      x: e.pageX - rel.x,
      y: e.pageY - rel.y
    });
    e.stopPropagation();
    e.preventDefault();
  };

  const onMouseUp = () => {
    setDragging(false);
  };

  useEffect(() => {
    if (dragging) {
      document.addEventListener("mousemove", onMouseMove);
      document.addEventListener("mouseup", onMouseUp);
    } else {
      document.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("mouseup", onMouseUp);
    }

    return () => {
      document.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("mouseup", onMouseUp);
    };
  }, [dragging]);

  // Load chat history from localStorage
  useEffect(() => {
    const savedMessages = localStorage.getItem('cybersecurityChatHistory');
    if (savedMessages) {
      setChatMessages(JSON.parse(savedMessages));
    }
    fetchTelegramLink();
  }, []);

  const fetchTelegramLink = async () => {
    try {
      const response = await axios.get('https://localhost:5000/api/telegram/bot-info');
      if (response.data.success) {
        setTelegramLink(response.data.botLink);
      }
    } catch (error) {
      console.error('Error fetching Telegram bot info:', error);
      setTelegramLink('https://t.me/SafeNett_bot');
    }
  };
  useEffect(() => {
    if (chatMessages.length > 0) {
      localStorage.setItem('cybersecurityChatHistory', JSON.stringify(chatMessages));
    }
  }, [chatMessages]);

  useEffect(() => {
    if (chatContainerRef.current) {
      chatContainerRef.current.scrollTop = chatContainerRef.current.scrollHeight;
    }
  }, [chatMessages]);

  const toggleChatbot = () => {
    setIsOpen((prev) => !prev);
    if (!isOpen) {
      setChatMode("main");
      setSelectedService(null);
      setUserText("");
      setSelectedFile(null);
      setResult(null);
    }
  };

  const handleTelegramClick = () => {
    if (telegramLink) {
      window.open(telegramLink, '_blank');
    }
  };
  const services = [
    { name: "Scan URL", type: "scan_url" },
    { name: "Scan Email", type: "scan_email" },
    { name: "Report URL", type: "report_url" },
    
  ];

  const handleServiceSelection = (service) => {
    console.log("Service selected:", service.type);
    setSelectedService(service);
    setResult(null);
    setUserText("");
    setSelectedFile(null);
  };

  const addMessage = (type, content) => {
    const newMessage = {
      type,
      content,
      timestamp: new Date().toISOString()
    };
    setChatMessages(prev => [...prev, newMessage]);
  };

  const handleAskAISubmit = async () => {
    if (!userText.trim()) return;
    
    const question = userText.trim();
    setUserText("");
    addMessage('user', question);
    setIsLoading(true);

    try {
      const conversationHistory = chatMessages.slice(-10).map(msg => ({
        role: msg.type === 'user' ? 'user' : 'assistant',
        content: msg.content
      }));

      console.log("Sending userId to backend:", user?.id);

      const response = await axios.post(
        "https://localhost:5000/api/ask-ai",
        { 
          question,
          conversationHistory,
          userId: user?.id
        },
        { withCredentials: true }
      );

      if (response.data.message) {
        addMessage('bot', response.data.message);
      } else {
        addMessage('bot', '⚠️ Error: ' + (response.data.error || 'Unknown error occurred'));
      }

    } catch (err) {
      console.error("Failed to get AI answer:", err);
      addMessage('bot', 'Sorry, I encountered an error. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const formatEmailScanResult = (data) => {
    const finalVerdict = data.finalVerdict || '⚠️ Unable to determine';
    const explanation = data.finalVerdictExplanation || 'No detailed explanation available.';
    const headerVerdict = data.emailHeaderFinalVerdict || '';
    return (
      <div className="email-scan-result">
        <h3>🔍 Email Scan Complete</h3>
        
        <div className="email-verdict-section">
          <span className="email-verdict-label">Final Verdict:</span>
          <div className="email-verdict-value">{finalVerdict}</div>
        </div>
        
        <div className="email-explanation-section">
          <span className="email-explanation-label">Why?</span>
          <div className="email-explanation-text">{explanation}</div>
        </div>
        
        {headerVerdict && (
          <div className="email-header-section">
            <span className="email-header-label">Email Header Analysis:</span>
            <div className="email-header-text">{headerVerdict}</div>
          </div>
        )}
        
        <div className="email-info-box">
          <p className="email-info-title">📊 <strong>For more details scan it on our webpage:</strong></p>
          <a 
            href="https://localhost:3000/scan-email" 
            target="_blank" 
            rel="noopener noreferrer"
            className="email-info-link"
          >
            🔗 Visit SafeNet Scanner
          </a>
        </div>
        
        <p className="email-footer-message">
          <em>Stay safe online!</em> 🛡️
        </p>
      </div>
    );
  };
  const handleSubmit = () => {
    if (chatMode === "askai") {
      handleAskAISubmit();
    } else if (chatMode === "services") {
      if (!selectedService) return;
      console.log("Submitting service call for:", selectedService.type);
      console.log("User input:", userText, "Selected File:", selectedFile);
      
      if (selectedService.type === "scan_url") {
        setResult({ loading: true });
        axios
          .post(
            "https://localhost:5000/api/scan-url",
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
            "https://localhost:5000/api/report-url",
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
        formData.append("emlFile", selectedFile);
        console.log("FormData prepared with file:", selectedFile.name);
        setResult({ loading: true });
        
        axios
          .post("https://localhost:5000/api/scan-eml-file", formData, {
            withCredentials: true
          })
          .then((res) => {
            console.log("Response from scan-eml-file:", res.data);
            setResult(res.data);
          })
          .catch((err) => {
            console.error("Error in scan_eml_file axios call:", err);
            setResult({ error: "Failed to scan email. Please try scanning it on our webpage." });
          });
      } 
    }
  };
  const handleTextKeyDown = (e) => {
    if (e.key === "Enter") handleSubmit();
  };

  const clearChatHistory = () => {
    if (window.confirm('Are you sure you want to clear the chat history?')) {
      setChatMessages([]);
      localStorage.removeItem('cybersecurityChatHistory');
    }
  };

  // Render the main menu with two buttons
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
          onClick={() => {
            setChatMode("askai");
            if (chatMessages.length === 0) {
              addMessage('bot', 'Hello! I\'m your cybersecurity assistant. I can help you with questions about network security, encryption, vulnerabilities, ethical hacking, and other cybersecurity topics. How can I assist you today?');
            }
          }}
        >
          Ask AI
        </button>
      </div>
    );
  };

  // Render the Ask AI interface with chat history.
  const renderAskAIMode = () => {
    return (
      <div className="ask-ai-container">
        <div className="ask-ai-header">
          <h4>Ask AI - Cybersecurity Assistant</h4>
          <button 
            className="clear-chat-button"
            onClick={clearChatHistory}
            title="Clear chat history"
          >
            Clear
          </button>
        </div>
        
        <div className="chat-messages" ref={chatContainerRef}>
          {chatMessages.map((message, index) => (
            <div key={index} className={`chat-message ${message.type}-message`}>
              <div className="message-icon">
                {message.type === 'user' ? '👤' : '🤖'}
              </div>
              <div className="message-content">
                {message.content}
              </div>
            </div>
          ))}
          {isLoading && (
            <div className="chat-message bot-message">
              <div className="message-icon">🤖</div>
              <div className="message-content typing-indicator">
                <span></span>
                <span></span>
                <span></span>
              </div>
            </div>
          )}
        </div>
        
        <div className="ask-ai-input-container">
          <input
            type="text"
            value={userText}
            placeholder="Ask a cybersecurity question..."
            onChange={(e) => setUserText(e.target.value)}
            onKeyDown={handleTextKeyDown}
            className="ask-ai-input"
            disabled={isLoading}
          />
          <button 
            onClick={handleSubmit} 
            className="submit-button"
            disabled={isLoading || !userText.trim()}
          >
            Send
          </button>
        </div>
        
        <button
          className="back-button"
          onClick={() => {
            setChatMode("main");
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
      if (result.loading) {
        resultContent = (
          <div className="result-area" style={{ textAlign: 'center', padding: '20px' }}>
            <div className="loading-spinner">🔍 Scanning{selectedService && selectedService.type === 'scan_url' ? ' URL' : ' email file'}...</div>
          </div>
        );
      } else if (result.error) {
          resultContent = (
            <div className="result-area">
              <div className="error-container">
                <h4 className="error-title">❌ {result.error}</h4>
                <div className="error-info-box">
                  <p className="error-info-text">📊 <strong>Try scanning it on our webpage:</strong></p>
                  <a 
                    href="https://localhost:3000/home"
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="error-info-link"
                  >
                    🔗 Visit SafeNet Scanner
                  </a>
                </div>
              </div>
            </div>
          );
        } else if (selectedService && selectedService.type === "scan_email") {
        resultContent = (
          <div className="result-area">
            {formatEmailScanResult(result)}
          </div>
        );
      } else if (selectedService && selectedService.type === "scan_url") {
      resultContent = (
        <div className="result-area">
          <div className="scan-url-result">
            {result.scan_report && (
              <div>
                <pre className="scan-url-report">{result.scan_report}</pre>
              </div>
            )}
            {!result.scan_report && (
              <div>
                <strong>Raw Response:</strong>
                <pre className="scan-url-report">{JSON.stringify(result, null, 2)}</pre>
              </div>
            )}
          </div>
        </div>
      );
    } else if (selectedService && selectedService.type === "report_url") {
      resultContent = (
        <div className="result-area">
          <div className="report-url-result">
            <h3>🚨 URL Report Submitted</h3>
            {result.message && (
              <p><strong>Status:</strong> {result.message}</p>
            )}
            {result.url && (
              <p><strong>Reported URL:</strong> {result.url}</p>
            )}
            {result.reportId && (
              <p><strong>Report ID:</strong> {result.reportId}</p>
            )}
            <p><em>Thank you for contributing to a safer web.</em> 🛡️</p>
          </div>
        </div>
      );
    } else {
      const reportText = JSON.stringify(result, null, 2);
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

    }
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
    
    if (chatMode === "services" && resultContent) {
      chatbotContent = (
        <div>
          {chatbotContent}
          {resultContent}
        </div>
      );
    }
  
    // Chatbot window with a header that displays the chatbot logo centered.
    const chatbotWindow = isOpen ? (
      <div
        className="chatbot-window"
        ref={chatbotRef}
        style={{
          top: position.y,
          left: position.x,
          position: "fixed",
          zIndex: 10000
        }}
      >
        <div className="chatbot-header" onMouseDown={onMouseDown}>
          <img
            src={chatbotIcon}
            alt="Chatbot Logo"
            className="chatbot-logo"
          />
        </div>
        {chatbotContent}
      </div>
    ) : null;
  
    // The buttons container with chatbot and Telegram
    return (
      <div className="chatbot-container">
        {chatbotWindow}
        <div className="floating-buttons">
          <button 
            className="telegram-toggle" 
            onClick={handleTelegramClick}
            title="Chat on Telegram"
          >
            <img src={telegramIcon} alt="Telegram" className="telegram-icon" />
          </button>
          <button className="chatbot-toggle" onClick={toggleChatbot}>
            <img src={chatbotIcon} alt="Chatbot" className="chatbot-icon" />
          </button>
        </div>
      </div>
    );
  };
  
  export default Chatbot;