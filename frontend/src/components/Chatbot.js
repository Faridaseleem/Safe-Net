// src/components/Chatbot.js
import React, { useState, useEffect, useRef } from "react";
import axios from "axios";
import "./Chatbot.css";
import chatbotIcon from "./chatbot.png";
import telegramIcon from "./telegram.png"; // Add this import

const Chatbot = () => {
  // General chatbot states.
  const [isOpen, setIsOpen] = useState(false);
  const [chatMode, setChatMode] = useState("main");
  const [selectedService, setSelectedService] = useState(null);
  const [userText, setUserText] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);
  const [result, setResult] = useState(null);

  // New states for Ask AI chat functionality
  const [chatMessages, setChatMessages] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const chatContainerRef = useRef(null);

  // Telegram link state
  const [telegramLink, setTelegramLink] = useState("");

  // Draggable state
  const chatbotRef = useRef(null);
  const [position, setPosition] = useState({ x: 60, y: 120 });
  const [dragging, setDragging] = useState(false);
  const [rel, setRel] = useState({ x: 0, y: 0 });

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

  // Load chat history from localStorage when component mounts
  useEffect(() => {
    const savedMessages = localStorage.getItem('cybersecurityChatHistory');
    if (savedMessages) {
      setChatMessages(JSON.parse(savedMessages));
    }
    
    // Fetch Telegram bot info
    fetchTelegramLink();
  }, []);

  // Fetch Telegram link from backend
  const fetchTelegramLink = async () => {
    try {
      const response = await axios.get('http://localhost:5000/api/telegram/bot-info');
      if (response.data.success) {
        setTelegramLink(response.data.botLink);
      }
    } catch (error) {
      console.error('Error fetching Telegram bot info:', error);
      setTelegramLink('https://t.me/SafeNett_bot');
    }
  };

  // Save chat messages to localStorage whenever they change
  useEffect(() => {
    if (chatMessages.length > 0) {
      localStorage.setItem('cybersecurityChatHistory', JSON.stringify(chatMessages));
    }
  }, [chatMessages]);

  // Scroll to bottom when new messages are added
  useEffect(() => {
    if (chatContainerRef.current) {
      chatContainerRef.current.scrollTop = chatContainerRef.current.scrollHeight;
    }
  }, [chatMessages]);

  // Toggle the chatbot window open/close.
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

  // Handle Telegram button click
  const handleTelegramClick = () => {
    if (telegramLink) {
      window.open(telegramLink, '_blank');
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

  // Add message to chat history
  const addMessage = (type, content) => {
    const newMessage = {
      type,
      content,
      timestamp: new Date().toISOString()
    };
    setChatMessages(prev => [...prev, newMessage]);
  };

  // Handle Ask AI submission
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

      const response = await axios.post(
        "http://localhost:5000/api/ask-ai",
        { 
          question,
          conversationHistory 
        },
        { withCredentials: true }
      );

      if (response.data.answer) {
        addMessage('bot', response.data.answer);
      } else {
        addMessage('bot', 'Sorry, I couldn\'t process your request. Please try again.');
      }
    } catch (err) {
      console.error("Failed to get AI answer:", err);
      addMessage('bot', 'Sorry, I encountered an error. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  // Add a function to format email scan results
  const formatEmailScanResult = (data) => {
    // Extract the verdict and explanation
    const finalVerdict = data.finalVerdict || '⚠️ Unable to determine';
    const explanation = data.finalVerdictExplanation || 'No detailed explanation available.';
    const headerVerdict = data.emailHeaderFinalVerdict || '';
    
    // Create formatted HTML result
    return (
      <div className="email-scan-result">
        <h3 style={{ color: '#4CAF50', marginBottom: '15px' }}>🔍 Email Scan Complete</h3>
        
        <div style={{ marginBottom: '15px' }}>
          <strong>Final Verdict:</strong>
          <div style={{ fontSize: '1.1em', marginTop: '5px' }}>{finalVerdict}</div>
        </div>
        
        <div style={{ marginBottom: '15px' }}>
          <strong>Why?</strong>
          <div style={{ marginTop: '5px', color: '#666' }}>{explanation}</div>
        </div>
        
        {headerVerdict && (
          <div style={{ marginBottom: '15px' }}>
            <strong>Email Header Analysis:</strong> {headerVerdict}
          </div>
        )}
        
        <div style={{ marginTop: '20px', padding: '10px', backgroundColor: '#f0f0f0', borderRadius: '5px' }}>
          <p style={{ margin: '0 0 10px 0' }}>📊 <strong>For more details scan it on our webpage:</strong></p>
          <a 
            href="http://localhost:3000/scan-email" 
            target="_blank" 
            rel="noopener noreferrer"
            style={{ color: '#2196F3', textDecoration: 'none' }}
          >
            🔗 Visit SafeNet Scanner
          </a>
        </div>
        
        <p style={{ marginTop: '15px', fontSize: '0.9em', color: '#666' }}>
          <em>Stay safe online!</em> 🛡️
        </p>
      </div>
    );
  };

  // The submit handler now distinguishes between Ask AI and Services.
  const handleSubmit = () => {
    if (chatMode === "askai") {
      handleAskAISubmit();
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
        formData.append("emlFile", selectedFile);
        console.log("FormData prepared with file:", selectedFile.name);
        
        // Show loading state
        setResult({ loading: true });
        
        axios
          .post("http://localhost:5000/api/scan-eml-file", formData, {
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

  // Clear chat history
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
      if (result.loading) {
        resultContent = (
          <div className="result-area" style={{ textAlign: 'center', padding: '20px' }}>
            <div className="loading-spinner">🔍 Scanning email file...</div>
          </div>
        );
      } else if (result.error) {
        resultContent = (
          <div className="result-area">
            <div style={{ color: '#f44336', padding: '15px' }}>
              <h4>❌ {result.error}</h4>
              <div style={{ marginTop: '15px', padding: '10px', backgroundColor: '#f0f0f0', borderRadius: '5px' }}>
                <p>📊 <strong>Try scanning it on our webpage:</strong></p>
                <a 
                  href="http://localhost:3000/scan-email"
                  target="_blank" 
                  rel="noopener noreferrer"
                  style={{ color: '#2196F3' }}
                >
                  🔗 Visit SafeNet Scanner
                </a>
              </div>
            </div>
          </div>
        );
      } else if (selectedService && selectedService.type === "scan_email") {
        // Special formatting for email scan results
        resultContent = (
          <div className="result-area">
            {formatEmailScanResult(result)}
          </div>
        );
      } else {
        // Default formatting for other services
        let reportText = "";
        if (
          selectedService &&
          (selectedService.type === "scan_url" ||
            selectedService.type === "report_url")
        ) {
          reportText = result.scan_report
            ? result.scan_report
            : JSON.stringify(result, null, 2);
        } else if (selectedService && selectedService.type === "education") {
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
    
    // For services mode, show results below the content
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