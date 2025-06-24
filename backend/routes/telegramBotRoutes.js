// routes/telegramBotRoutes.js
const express = require('express');
const router = express.Router();
const TelegramBot = require('node-telegram-bot-api');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

// Initialize bot WITHOUT polling to avoid conflicts
const token = process.env.TELEGRAM_BOT_TOKEN;
let bot;

// Check if we're in development or production
const isDevelopment = process.env.NODE_ENV !== 'production';

if (token) {
    // Always use polling: false to avoid 409 conflicts
    bot = new TelegramBot(token, { polling: false });
    
    // Only start polling if no other instance is running
    bot.startPolling()
        .then(() => {
            console.log('✅ Telegram bot started successfully');
        })
        .catch((error) => {
            if (error.code === 'ETELEGRAM' && error.response.body.error_code === 409) {
                console.log('⚠️ Another instance is already running. Bot initialized without polling.');
            } else {
                console.error('❌ Error starting bot:', error);
            }
        });
} else {
    console.log('⚠️ Telegram bot token not found in .env');
}

// Store user sessions
const userSessions = new Map();

// Initialize bot commands and handlers
if (bot) {
    // Set bot commands
    bot.setMyCommands([
        { command: '/start', description: 'Start the bot' },
        { command: '/menu', description: 'Show main menu' },
        { command: '/help', description: 'Show help information' },
        { command: '/clear', description: 'Clear chat history' }
    ]).catch(err => console.log('Error setting commands:', err));

    // Handle /start command
    bot.onText(/\/start/, (msg) => {
        const chatId = msg.chat.id;
        const userName = msg.from.first_name || 'User';
        
        const welcomeMessage = `🔒 Welcome ${userName} to Cybersecurity Assistant!\n\n` +
            `I can help you with:\n` +
            `• Scanning URLs for threats\n` +
            `• Analyzing email files for phishing\n` +
            `• Reporting malicious URLs\n` +
            `• Answering cybersecurity questions\n\n` +
            `Use the buttons below or type /menu anytime!`;

        bot.sendMessage(chatId, welcomeMessage, {
            reply_markup: getMainMenuKeyboard()
        });
    });

    // Handle /menu command
    bot.onText(/\/menu/, (msg) => {
        const chatId = msg.chat.id;
        bot.sendMessage(chatId, '🔒 Choose a service:', {
            reply_markup: getMainMenuKeyboard()
        });
    });

    // Handle /help command
    bot.onText(/\/help/, (msg) => {
        const chatId = msg.chat.id;
        const helpText = `📚 *How to use this bot:*\n\n` +
            `1️⃣ *Scan URL* - Check if a URL is safe\n` +
            `2️⃣ *Report URL* - Report a malicious URL\n` +
            `3️⃣ *Scan Email* - Analyze .eml files for threats\n` +
            `4️⃣ *Ask AI* - Ask cybersecurity questions\n\n` +
            `You can use the menu buttons or type commands directly.\n\n` +
            `*Commands:*\n` +
            `/start - Start the bot\n` +
            `/menu - Show main menu\n` +
            `/help - Show this help\n` +
            `/clear - Clear chat history`;
        
        bot.sendMessage(chatId, helpText, { parse_mode: 'Markdown' });
    });

    // Handle /clear command
    bot.onText(/\/clear/, (msg) => {
        const chatId = msg.chat.id;
        const userId = msg.from.id;
        
        if (userSessions.has(userId)) {
            userSessions.get(userId).chatHistory = [];
            bot.sendMessage(chatId, '✅ Chat history cleared!');
        } else {
            bot.sendMessage(chatId, '📭 No chat history to clear.');
        }
    });

    // Handle callback queries (button presses)
    bot.on('callback_query', async (callbackQuery) => {
        const chatId = callbackQuery.message.chat.id;
        const userId = callbackQuery.from.id;
        const data = callbackQuery.data;

        // Answer callback query to remove loading state
        bot.answerCallbackQuery(callbackQuery.id);

        // Initialize user session if not exists
        if (!userSessions.has(userId)) {
            userSessions.set(userId, {
                mode: null,
                chatHistory: [],
                waitingFor: null
            });
        }

        const session = userSessions.get(userId);

        switch (data) {
            case 'scan_url':
                session.mode = 'scan_url';
                session.waitingFor = 'url';
                bot.sendMessage(chatId, '🔍 Please send me the URL you want to scan.\n\nExample: `https://example.com`', {
                    parse_mode: 'Markdown',
                    reply_markup: getCancelKeyboard()
                });
                break;

            case 'report_url':
                session.mode = 'report_url';
                session.waitingFor = 'url';
                bot.sendMessage(chatId, '⚠️ Please send me the suspicious URL you want to report.\n\nExample: `https://suspicious-site.com`', {
                    parse_mode: 'Markdown',
                    reply_markup: getCancelKeyboard()
                });
                break;

            case 'scan_email':
                session.mode = 'scan_email';
                session.waitingFor = 'file';
                bot.sendMessage(chatId, 
                    '📧 *Email File Scanner*\n\n' +
                    'Please send me an `.eml` file to scan for phishing and security threats.\n\n' +
                    '*How to get an .eml file:*\n' +
                    '• Gmail: Open email → 3 dots → Download message\n' +
                    '• Outlook: Open email → File → Save as\n' +
                    '• Thunderbird: Right-click email → Save as', {
                    parse_mode: 'Markdown',
                    reply_markup: getCancelKeyboard()
                });
                break;

            case 'ask_ai':
                session.mode = 'ask_ai';
                session.waitingFor = 'question';
                bot.sendMessage(chatId, 
                    '🤖 *AI Cybersecurity Assistant*\n\n' +
                    'I can answer questions about:\n' +
                    '• Network security\n' +
                    '• Encryption & cryptography\n' +
                    '• Vulnerabilities & exploits\n' +
                    '• Ethical hacking\n' +
                    '• Malware protection\n' +
                    '• Security best practices\n\n' +
                    'Please type your question:', {
                    parse_mode: 'Markdown',
                    reply_markup: getCancelKeyboard()
                });
                break;

            case 'cancel':
                session.mode = null;
                session.waitingFor = null;
                bot.sendMessage(chatId, '❌ Operation cancelled.', {
                    reply_markup: getMainMenuKeyboard()
                });
                break;

            case 'main_menu':
                session.mode = null;
                session.waitingFor = null;
                bot.sendMessage(chatId, '🔒 Main Menu:', {
                    reply_markup: getMainMenuKeyboard()
                });
                break;
        }
    });

    // Handle document uploads (for email scanning)
    bot.on('document', async (msg) => {
        const chatId = msg.chat.id;
        const userId = msg.from.id;
        
        // Check if user has a session and is waiting for email file
        if (!userSessions.has(userId)) {
            userSessions.set(userId, {
                mode: null,
                chatHistory: [],
                waitingFor: null
            });
        }
        
        const session = userSessions.get(userId);
        
        if (session.mode === 'scan_email' && session.waitingFor === 'file') {
            const fileId = msg.document.file_id;
            const fileName = msg.document.file_name;
            
            // Check if it's an .eml file
            if (!fileName || !fileName.toLowerCase().endsWith('.eml')) {
                bot.sendMessage(chatId, '❌ Please upload a valid .eml file.', {
                    reply_markup: getCancelKeyboard()
                });
                return;
            }
            
            await handleEmailScan(chatId, fileId, fileName, session);
        } else {
            bot.sendMessage(chatId, 'Please use the menu to select a service first:', {
                reply_markup: getMainMenuKeyboard()
            });
        }
    });

    // Handle regular messages
    bot.on('message', async (msg) => {
        // Skip if it's a command or document
        if ((msg.text && msg.text.startsWith('/')) || msg.document) return;

        const chatId = msg.chat.id;
        const userId = msg.from.id;
        const text = msg.text;

        // Initialize session if not exists
        if (!userSessions.has(userId)) {
            userSessions.set(userId, {
                mode: null,
                chatHistory: [],
                waitingFor: null
            });
        }

        const session = userSessions.get(userId);

        // Handle based on what we're waiting for
        if (session.waitingFor === 'url' && text) {
            await handleURL(chatId, text, session.mode, session);
        } else if (session.waitingFor === 'question' && text) {
            await handleAskAI(chatId, text, session);
        } else if (text) {
            // Default response
            bot.sendMessage(chatId, 'Please use the menu to select a service:', {
                reply_markup: getMainMenuKeyboard()
            });
        }
    });
}

// Main menu keyboard
function getMainMenuKeyboard() {
    return {
        inline_keyboard: [
            [
                { text: '🔍 Scan URL', callback_data: 'scan_url' },
                { text: '⚠️ Report URL', callback_data: 'report_url' }
            ],
            [
                { text: '📧 Scan Email', callback_data: 'scan_email' },
                { text: '🤖 Ask AI', callback_data: 'ask_ai' }
            ]
        ]
    };
}

// Cancel operation keyboard
function getCancelKeyboard() {
    return {
        inline_keyboard: [
            [{ text: '❌ Cancel', callback_data: 'cancel' }]
        ]
    };
}

// Back to menu keyboard
function getBackToMenuKeyboard() {
    return {
        inline_keyboard: [
            [{ text: '📋 Back to Menu', callback_data: 'main_menu' }]
        ]
    };
}

// Handle URL scanning/reporting
async function handleURL(chatId, url, mode, session) {
    session.waitingFor = null;

    // Validate URL
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
    }

    // Send typing action
    bot.sendChatAction(chatId, 'typing');

    try {
        const endpoint = mode === 'scan_url' 
            ? 'http://localhost:5000/api/scan-url'
            : 'http://localhost:5000/api/report-url';

        const response = await axios.post(endpoint, { url });
        
        let resultMessage = `✅ *${mode === 'scan_url' ? 'URL Scan' : 'URL Report'} Results*\n\n`;
        resultMessage += `🔗 *URL:* \`${url}\`\n\n`;
        
        if (response.data.scan_report) {
            resultMessage += response.data.scan_report;
        } else if (response.data.message) {
            resultMessage += response.data.message;
        } else {
            resultMessage += '```\n' + JSON.stringify(response.data, null, 2) + '\n```';
        }

        bot.sendMessage(chatId, resultMessage, {
            parse_mode: 'Markdown',
            reply_markup: getBackToMenuKeyboard()
        });

    } catch (error) {
        console.error('Error:', error);
        bot.sendMessage(chatId, '❌ Error processing URL. Please try again.', {
            reply_markup: getBackToMenuKeyboard()
        });
    }
}

// Handle Email scanning
// Handle Email scanning
// Handle Email scanning with comprehensive report
async function handleEmailScan(chatId, fileId, fileName, session) {
    session.waitingFor = null;

    bot.sendChatAction(chatId, 'upload_document');

    try {
        // Get file info from Telegram
        const file = await bot.getFile(fileId);
        const filePath = file.file_path;
        
        // Download file from Telegram
        const downloadUrl = `https://api.telegram.org/file/bot${token}/${filePath}`;
        const response = await axios.get(downloadUrl, { responseType: 'arraybuffer' });
        
        // Create form data for API
        const FormData = require('form-data');
        const formData = new FormData();
        formData.append('emlFile', Buffer.from(response.data), {
            filename: fileName,
            contentType: 'message/rfc822'
        });

        // Send to your scan API
        const scanResponse = await axios.post('http://localhost:5000/api/scan-eml-file', formData, {
            headers: {
                ...formData.getHeaders()
            }
        });

        // Get the response from backend
        const result = scanResponse.data;
        
        // Function to escape special characters for Telegram
        const escape = (text) => {
            if (!text) return 'N/A';
            return text.toString()
                .replace(/\\/g, '\\\\')
                .replace(/\*/g, '\\*')
                .replace(/_/g, '\\_')
                .replace(/\[/g, '\$$')
                .replace(/$$/g, '\\]')
                .replace(/\(/g, '\$$')
                .replace(/$$/g, '\\)')
                .replace(/~/g, '\\~')
                .replace(/`/g, '\\`')
                .replace(/>/g, '\\>')
                .replace(/#/g, '\\#')
                .replace(/\+/g, '\\+')
                .replace(/-/g, '\\-')
                .replace(/=/g, '\\=')
                .replace(/\|/g, '\\|')
                .replace(/\{/g, '\\{')
                .replace(/\}/g, '\\}')
                .replace(/\./g, '\\.')
                .replace(/!/g, '\\!');
        };

        // Calculate overall risk score
        let totalRiskScore = 0;
        let riskFactors = 0;

        if (result.spamScore) {
            totalRiskScore += result.spamScore * 10;
            riskFactors++;
        }
        if (result.phishingScore) {
            totalRiskScore += result.phishingScore;
            riskFactors++;
        }
        if (result.suspiciousContent) {
            totalRiskScore += 50;
            riskFactors++;
        }
        if (result.spfStatus !== 'pass') {
            totalRiskScore += 30;
            riskFactors++;
        }
        if (result.dkimStatus !== 'pass') {
            totalRiskScore += 30;
            riskFactors++;
        }

        const aggregatedRiskScore = riskFactors > 0 ? Math.round(totalRiskScore / riskFactors) : 0;
        
        // Determine verdict
        let verdict, verdictEmoji;
        if (aggregatedRiskScore >= 70) {
            verdict = 'High Risk \$$Likely Malicious\$$';
            verdictEmoji = '🔴';
        } else if (aggregatedRiskScore >= 40) {
            verdict = 'Medium Risk \$$Potentially Unsafe\$$';
            verdictEmoji = '🟠';
        } else {
            verdict = 'Low Risk \$$Likely Safe\$$';
            verdictEmoji = '🟢';
        }

        // Build comprehensive report
        let report = `*Email Scan Results:*\n\n`;
        
        // Header Analysis
        report += `*Header Analysis:*\n`;
        report += `• *From:* ${escape(result.from || 'Unknown')}\n`;
        report += `• *To:* ${escape(result.to || 'Unknown')}\n`;
        report += `• *Subject:* ${escape(result.subject || 'No Subject')}\n`;
        report += `• *Date:* ${escape(result.date ? new Date(result.date).toLocaleString() : 'Unknown')}\n`;
        report += `• *Message\\-ID:* ${escape(result.messageId || 'Not Found')}\n`;
        
        report += `\n*Aggregated Verdict:* ${verdictEmoji} ${verdict}\n`;
        report += `*Aggregated Risk Score:* ${aggregatedRiskScore}/100\n\n`;

        // Authentication Results
        report += `*Authentication Results:*\n`;
        
        if (result.spfStatus) {
            const spfEmoji = result.spfStatus === 'pass' ? '✅' : '❌';
            const spfRisk = result.spfStatus === 'pass' ? 0 : 30;
            report += `• *SPF Check:* ${spfEmoji} ${escape(result.spfStatus.toUpperCase())}\n`;
            report += `  Risk Contribution: ${spfRisk}/100\n`;
        }
        
        if (result.dkimStatus) {
            const dkimEmoji = result.dkimStatus === 'pass' ? '✅' : '❌';
            const dkimRisk = result.dkimStatus === 'pass' ? 0 : 30;
            report += `• *DKIM Check:* ${dkimEmoji} ${escape(result.dkimStatus.toUpperCase())}\n`;
            report += `  Risk Contribution: ${dkimRisk}/100\n`;
        }
        
        if (result.dmarcStatus) {
            const dmarcEmoji = result.dmarcStatus === 'pass' ? '✅' : '❌';
            report += `• *DMARC Check:* ${dmarcEmoji} ${escape(result.dmarcStatus.toUpperCase())}\n`;
        }

        // URL/Link Analysis
        if (result.links && result.links.length > 0) {
            report += `\n*URL Scan Results:*\n\n`;
            
            for (let i = 0; i < Math.min(result.links.length, 5); i++) {
                const link = result.links[i];
                
                // Analyze each link
                let linkRisk = 0;
                let linkVerdict = 'Safe';
                let linkEmoji = '🟢';
                
                // Check for suspicious patterns
                if (link.includes('bit.ly') || link.includes('tinyurl') || link.includes('goo.gl')) {
                    linkRisk = 60;
                    linkVerdict = 'Suspicious \$$URL Shortener\$$';
                    linkEmoji = '🟠';
                } else if (!link.includes('https://')) {
                    linkRisk = 40;
                    linkVerdict = 'Warning \$$Not Secure\$$';
                    linkEmoji = '🟡';
                }
                
                // Check for homograph attacks
                const suspiciousPatterns = /[а-яА-Я]|[αβγδεζηθικλμνξοπρστυφχψω]/;
                if (suspiciousPatterns.test(link)) {
                    linkRisk = 80;
                    linkVerdict = 'High Risk \$$Possible Homograph\$$';
                    linkEmoji = '🔴';
                }
                
                report += `• *${escape(link.substring(0, 50))}${link.length > 50 ? '\\.\\.\\.' : ''}*\n`;
                report += `  Verdict: ${linkEmoji} ${linkVerdict}\n`;
                report += `  Risk Score: ${linkRisk}/100\n\n`;
            }
            
            if (result.links.length > 5) {
                report += `_\\.\\.\\. and ${result.links.length - 5} more URLs_\n`;
            }
        }

        // Attachment Analysis
        if (result.attachments && result.attachments.length > 0) {
            report += `\n*Attachment Scan Results:*\n\n`;
            
            result.attachments.forEach((att, index) => {
                const attName = escape(att.filename || `Attachment ${index + 1}`);
                const extension = att.filename ? att.filename.split('.').pop().toLowerCase() : 'unknown';
                
                // Determine risk based on file type
                let attRisk = 0;
                let attVerdict = 'Safe';
                let attEmoji = '🟢';
                
                const dangerousExtensions = ['exe', 'scr', 'vbs', 'js', 'com', 'bat', 'cmd', 'pif'];
                const suspiciousExtensions = ['zip', 'rar', 'docm', 'xlsm', 'pptm'];
                
                if (dangerousExtensions.includes(extension)) {
                    attRisk = 90;
                    attVerdict = 'High Risk \$$Executable\$$';
                    attEmoji = '🔴';
                } else if (suspiciousExtensions.includes(extension)) {
                    attRisk = 60;
                    attVerdict = 'Medium Risk \$$Potentially Unsafe\$$';
                    attEmoji = '🟠';
                }
                
                report += `• *${attName}*\n`;
                report += `  Type: \\.${extension}\n`;
                if (att.size) {
                    report += `  Size: ${(att.size / 1024).toFixed(1)} KB\n`;
                }
                report += `  Verdict: ${attEmoji} ${attVerdict}\n`;
                report += `  Risk Score: ${attRisk}/100\n\n`;
            });
        }

        // Content Analysis
        if (result.suspiciousContent || result.spamScore || result.phishingScore) {
            report += `\n*Content Analysis:*\n`;
            
            if (result.suspiciousContent) {
                report += `• *Suspicious Content:* ⚠️ Detected\n`;
            }
            
            if (result.spamScore !== undefined) {
                const spamBar = '█'.repeat(Math.floor(result.spamScore)) + '░'.repeat(10 - Math.floor(result.spamScore));
                report += `• *Spam Score:* \$$${spamBar}\$$ ${result.spamScore}/10\n`;
            }
            
            if (result.phishingScore !== undefined) {
                const phishBar = '█'.repeat(Math.floor(result.phishingScore / 10)) + '░'.repeat(10 - Math.floor(result.phishingScore / 10));
                report += `• *Phishing Probability:* \$$${phishBar}\$$ ${result.phishingScore}%\n`;
            }
        }

        // Final Recommendations
        report += `\n*Recommendations:*\n`;
        if (aggregatedRiskScore >= 70) {
            report += `⛔ *DO NOT interact with this email*\n`;
            report += `• Delete immediately\n`;
            report += `• Report to IT security\n`;
            report += `• Do not click links or download attachments\n`;
        } else if (aggregatedRiskScore >= 40) {
            report += `⚠️ *Proceed with caution*\n`;
            report += `• Verify sender independently\n`;
            report += `• Scan attachments before opening\n`;
            report += `• Hover over links before clicking\n`;
        } else {
            report += `✅ *Email appears legitimate*\n`;
            report += `• Standard precautions apply\n`;
            report += `• Verify unexpected requests\n`;
            report += `• Keep security software updated\n`;
        }

        // Analysis Summary
        report += `\n━━━━━━━━━━━━━━━━━━━━━━\n`;
        report += `🕐 *Scanned:* ${escape(new Date().toLocaleTimeString())}\n`;
        report += `📄 *File:* ${escape(fileName)}\n`;
        report += `🔍 *Total Elements Analyzed:* ${(result.links?.length || 0) + (result.attachments?.length || 0) + 3} items`;

        // Check message length and split if necessary
        if (report.length > 4000) {
            // Split the report into multiple messages
            const parts = [];
            let currentPart = '';
            const lines = report.split('\n');
            
            for (const line of lines) {
                if (currentPart.length + line.length > 3900) {
                    parts.push(currentPart);
                    currentPart = line + '\n';
                } else {
                    currentPart += line + '\n';
                }
            }
            if (currentPart) parts.push(currentPart);
            
            // Send each part
            for (let i = 0; i < parts.length; i++) {
                await bot.sendMessage(chatId, parts[i], {
                    parse_mode: 'Markdown'
                });
                // Small delay between messages
                await new Promise(resolve => setTimeout(resolve, 500));
            }
            
            // Send menu after all parts
            bot.sendMessage(chatId, 'Email analysis complete\\.', {
                parse_mode: 'Markdown',
                reply_markup: getBackToMenuKeyboard()
            });
        } else {
            // Send as single message
            bot.sendMessage(chatId, report, {
                parse_mode: 'Markdown',
                reply_markup: getBackToMenuKeyboard()
            });
        }

    } catch (error) {
        console.error('Error scanning email:', error);
        
        // If Markdown parsing fails, try plain text
        if (error.message && error.message.includes("can't parse entities")) {
            try {
                // Retry with plain text
                await handleEmailScanPlainText(chatId, fileId, fileName, session);
            } catch (retryError) {
                bot.sendMessage(chatId, '❌ Error scanning email. The file may be corrupted or too complex to analyze.', {
                    reply_markup: getBackToMenuKeyboard()
                });
            }
        } else {
            let errorMessage = '❌ Email Scan Failed\n\n';
            
            if (error.response && error.response.data && error.response.data.error) {
                errorMessage += `Reason: ${error.response.data.error}\n\n`;
            } else {
                errorMessage += 'Unable to scan the email file.\n\n';
            }
            
            errorMessage += '📌 Possible reasons:\n';
            errorMessage += '• Invalid or corrupted .eml file\n';
            errorMessage += '• File too large\n';
            errorMessage += '• Server temporarily unavailable\n\n';
            errorMessage += 'Please try again with a valid .eml file.';
            
            bot.sendMessage(chatId, errorMessage, {
                reply_markup: getBackToMenuKeyboard()
            });
        }
    }
}

// Fallback plain text version for complex emails
async function handleEmailScanPlainText(chatId, fileId, fileName, session) {
    session.waitingFor = null;

    bot.sendChatAction(chatId, 'upload_document');

    try {
        // Get file info from Telegram
        const file = await bot.getFile(fileId);
        const filePath = file.file_path;
        
        // Download file from Telegram
        const downloadUrl = `https://api.telegram.org/file/bot${token}/${filePath}`;
        const response = await axios.get(downloadUrl, { responseType: 'arraybuffer' });
        
        // Create form data for API
        const FormData = require('form-data');
        const formData = new FormData();
        formData.append('emlFile', Buffer.from(response.data), {
            filename: fileName,
            contentType: 'message/rfc822'
        });

        // Send to your scan API
        const scanResponse = await axios.post('http://localhost:5000/api/scan-eml-file', formData, {
            headers: {
                ...formData.getHeaders()
            }
        });

        const result = scanResponse.data;
        
        // Calculate risk score
        let totalRiskScore = 0;
        let riskFactors = 0;

        if (result.spamScore) {
            totalRiskScore += result.spamScore * 10;
            riskFactors++;
        }
        if (result.phishingScore) {
            totalRiskScore += result.phishingScore;
            riskFactors++;
        }
        if (result.suspiciousContent) {
            totalRiskScore += 50;
            riskFactors++;
        }
        if (result.spfStatus !== 'pass') {
            totalRiskScore += 30;
            riskFactors++;
        }

        const aggregatedRiskScore = riskFactors > 0 ? Math.round(totalRiskScore / riskFactors) : 0;
        
        // Build plain text report
        let report = 'EMAIL SCAN RESULTS\n';
        report += '══════════════════\n\n';
        
        report += 'HEADER ANALYSIS:\n';
        report += `• From: ${result.from || 'Unknown'}\n`;
        report += `• To: ${result.to || 'Unknown'}\n`;
        report += `• Subject: ${result.subject || 'No Subject'}\n`;
        report += `• Date: ${result.date ? new Date(result.date).toLocaleString() : 'Unknown'}\n\n`;
        
        // Verdict
        let verdict;
        if (aggregatedRiskScore >= 70) {
            verdict = '🔴 HIGH RISK (Likely Malicious)';
        } else if (aggregatedRiskScore >= 40) {
            verdict = '🟠 MEDIUM RISK (Potentially Unsafe)';
        } else {
            verdict = '🟢 LOW RISK (Likely Safe)';
        }
        
        report += `VERDICT: ${verdict}\n`;
        report += `RISK SCORE: ${aggregatedRiskScore}/100\n\n`;
        
        // Authentication
        report += 'AUTHENTICATION:\n';
        if (result.spfStatus) {
            report += `• SPF: ${result.spfStatus === 'pass' ? '✅' : '❌'} ${result.spfStatus.toUpperCase()}\n`;
        }
        if (result.dkimStatus) {
            report += `• DKIM: ${result.dkimStatus === 'pass' ? '✅' : '❌'} ${result.dkimStatus.toUpperCase()}\n`;
        }
        if (result.dmarcStatus) {
            report += `• DMARC: ${result.dmarcStatus === 'pass' ? '✅' : '❌'} ${result.dmarcStatus.toUpperCase()}\n`;
        }
        
        // URLs
        if (result.links && result.links.length > 0) {
            report += `\nURLs FOUND: ${result.links.length}\n`;
            result.links.slice(0, 3).forEach((link, i) => {
                const truncated = link.length > 50 ? link.substring(0, 50) + '...' : link;
                report += `${i + 1}. ${truncated}\n`;
            });
            if (result.links.length > 3) {
                report += `... and ${result.links.length - 3} more\n`;
            }
        }
        
        // Attachments
        if (result.attachments && result.attachments.length > 0) {
            report += `\nATTACHMENTS: ${result.attachments.length}\n`;
            result.attachments.forEach((att, i) => {
                const name = att.filename || `Attachment ${i + 1}`;
                const size = att.size ? ` (${(att.size / 1024).toFixed(1)} KB)` : '';
                report += `${i + 1}. ${name}${size}\n`;
            });
        }
        
        // Recommendations
        report += '\nRECOMMENDATIONS:\n';
        if (aggregatedRiskScore >= 70) {
            report += '⛔ DO NOT interact with this email\n';
            report += '• Delete immediately\n';
            report += '• Report to IT security\n';
        } else if (aggregatedRiskScore >= 40) {
            report += '⚠️ Proceed with caution\n';
            report += '• Verify sender\n';
            report += '• Check links carefully\n';
        } else {
            report += '✅ Email appears safe\n';
            report += '• Standard precautions apply\n';
        }
        
        report += '\n══════════════════\n';
        report += `Scanned: ${new Date().toLocaleTimeString()}\n`;
        report += `File: ${fileName}`;

        // Send plain text report
        bot.sendMessage(chatId, report, {
            reply_markup: getBackToMenuKeyboard()
        });

    } catch (error) {
        console.error('Error in plain text scan:', error);
        bot.sendMessage(chatId, '❌ Failed to scan email file. Please ensure it is a valid .eml file.', {
            reply_markup: getBackToMenuKeyboard()
        });
    }
}
// Handle Ask AI
async function handleAskAI(chatId, question, session) {
    session.chatHistory.push({ role: 'user', content: question });

    // Send typing action
    bot.sendChatAction(chatId, 'typing');

    try {
        const response = await axios.post('http://localhost:5000/api/ask-ai', {
            question,
            conversationHistory: session.chatHistory.slice(-10)
        });

        const answer = response.data.answer;
        session.chatHistory.push({ role: 'assistant', content: answer });

        // Split long messages if needed (Telegram limit is 4096 characters)
        if (answer.length > 4000) {
            const chunks = answer.match(/.{1,4000}/g);
            for (const chunk of chunks) {
                await bot.sendMessage(chatId, chunk);
            }
        } else {
            await bot.sendMessage(chatId, answer);
        }

        // Send options for continuing
        setTimeout(() => {
            bot.sendMessage(chatId, 'Would you like to ask another question?', {
                reply_markup: {
                    inline_keyboard: [
                        [
                            { text: '✏️ Ask Another Question', callback_data: 'ask_ai' },
                            { text: '📋 Main Menu', callback_data: 'main_menu' }
                        ]
                    ]
                }
            });
        }, 1000);

    } catch (error) {
        console.error('Error:', error);
        bot.sendMessage(chatId, '❌ Sorry, I encountered an error. Please try again.', {
            reply_markup: getBackToMenuKeyboard()
        });
        session.waitingFor = null;
    }
}

// API endpoint to get bot info
router.get('/bot-info', (req, res) => {
    if (bot) {
        bot.getMe()
            .then(info => {
                res.json({
                    success: true,
                    botInfo: info,
                    botLink: `https://t.me/${info.username}`
                });
            })
            .catch(error => {
                res.status(500).json({ success: false, error: error.message });
            });
    } else {
        res.status(503).json({ success: false, error: 'Bot not initialized' });
    }
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('Shutting down Telegram bot...');
    if (bot) {
        bot.stopPolling();
    }
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('Shutting down Telegram bot...');
    if (bot) {
        bot.stopPolling();
    }
    process.exit(0);
});

module.exports = router;