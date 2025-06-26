const express = require('express');
const router = express.Router();
const TelegramBot = require('node-telegram-bot-api');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const token = process.env.TELEGRAM_BOT_TOKEN;
const botEnabled = process.env.ENABLE_BOT === 'true';
let bot;

// Only initialize bot if enabled
if (token && botEnabled) {
    bot = new TelegramBot(token, { polling: true });

    bot.on('polling_error', (error) => {
        if (error.response?.body?.error_code === 409) {
            console.log('⚠️ Another instance is already polling. Please disable other bots.');
        } else {
            console.log('❌ Polling error:', error.response?.body || error.message);
        }
    });

    console.log('✅ Telegram bot is ENABLED and started polling.');
} else if (!botEnabled) {
    console.log('⛔ Telegram bot is DISABLED via ENABLE_BOT flag.');
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
            ? 'https://localhost:5000/api/scan-url'
            : 'https://localhost:5000/api/report-url';

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



// Replace your formatEmailReport function with this simplified version
// Replace your formatEmailReport function with this version
function formatEmailReport(data) {
    let report = '';
    
    // Start with the header
    report += `*🔍 Email Scan Complete*\n\n`;
    
    // Get the final verdict and explanation from backend
    const finalVerdict = data.finalVerdict || '⚠️ Unable to determine';
    const explanation = data.finalVerdictExplanation || 'No detailed explanation available.';
    
    // Display the final verdict
    report += `*Final Verdict:*\n${finalVerdict}\n\n`;
    
    // Display the explanation/why
    report += `*Why?*\n${explanation}\n\n`;
    
    // Optional: Include email header verdict if you want to show both
    if (data.emailHeaderFinalVerdict) {
        report += `*Email Header Analysis:* ${data.emailHeaderFinalVerdict}\n\n`;
    }
    
    // Add the webpage link
    report += `📊 *For more details scan it on our webpage:*\n`;
    report += `🔗 [Visit SafeNet Scanner](https://your-website.com/email-scanner)\n\n`;
    report += `_Stay safe online!_ 🛡️`;
    
    return report;
}

// Update handleEmailScan to ensure we're getting the right data
async function handleEmailScan(chatId, fileId, fileName, session) {
    session.waitingFor = null;
    bot.sendChatAction(chatId, 'upload_document');

    try {
        // Get file info from Telegram
        const file = await bot.getFile(fileId);
        const filePath = file.file_path;
        
        // Download file from Telegram
        const downloadUrl = `https://api.telegram.org/file/bot${token}/${filePath}`;
        const fileResponse = await axios.get(downloadUrl, { responseType: 'arraybuffer' });
        
        // Create form data for API
        const FormData = require('form-data');
        const formData = new FormData();
        formData.append('emlFile', Buffer.from(fileResponse.data), {
            filename: fileName,
            contentType: 'message/rfc822'
        });

        // Send to your scan API
        const scanResponse = await axios.post('https://localhost:5000/api/scan-eml-file', formData, {
            headers: {
                ...formData.getHeaders()
            }
        });

        // Log to verify we're getting the expected fields
        console.log('Backend response fields:', {
            finalVerdict: scanResponse.data.finalVerdict,
            finalVerdictExplanation: scanResponse.data.finalVerdictExplanation,
            emailHeaderFinalVerdict: scanResponse.data.emailHeaderFinalVerdict
        });
        
        // Get the scan result
        const result = scanResponse.data;
        
        // Format the simple report
        const report = formatEmailReport(result);

        // Send the report
        await bot.sendMessage(chatId, report, {
            parse_mode: 'Markdown',
            reply_markup: getBackToMenuKeyboard(),
            disable_web_page_preview: false
        });

    } catch (error) {
        console.error('Error scanning email:', error);
        
        let errorMessage = '❌ *Email Scan Failed*\n\n';
        errorMessage += 'Unable to scan the email file.\n\n';
        errorMessage += '📊 *Try scanning it on our webpage:*\n';
        errorMessage += '🔗 [Visit SafeNet Scanner](https://localhost:3000/scan-email)';
        
        bot.sendMessage(chatId, errorMessage, {
            parse_mode: 'Markdown',
            reply_markup: getBackToMenuKeyboard(),
            disable_web_page_preview: false
        });
    }
}

// Also update handleEmailScan to log the response
async function handleEmailScan(chatId, fileId, fileName, session) {
    session.waitingFor = null;
    bot.sendChatAction(chatId, 'upload_document');

    try {
        // Get file info from Telegram
        const file = await bot.getFile(fileId);
        const filePath = file.file_path;
        
        // Download file from Telegram
        const downloadUrl = `https://api.telegram.org/file/bot${token}/${filePath}`;
        const fileResponse = await axios.get(downloadUrl, { responseType: 'arraybuffer' });
        
        // Create form data for API
        const FormData = require('form-data');
        const formData = new FormData();
        formData.append('emlFile', Buffer.from(fileResponse.data), {
            filename: fileName,
            contentType: 'message/rfc822'
        });

        // Send to your scan API
        const scanResponse = await axios.post('https://localhost:5000/api/scan-eml-file', formData, {
            headers: {
                ...formData.getHeaders()
            }
        });

        // Log the response to see what we're getting
        console.log('Email scan response:', JSON.stringify(scanResponse.data, null, 2));
        
        // Get the scan result
        const result = scanResponse.data;
        
        // Format the simple report
        const report = formatEmailReport(result);

        // Send the report
        await bot.sendMessage(chatId, report, {
            parse_mode: 'Markdown',
            reply_markup: getBackToMenuKeyboard(),
            disable_web_page_preview: false // Allow preview for the website link
        });

    } catch (error) {
        console.error('Error scanning email:', error);
        
        let errorMessage = '❌ *Email Scan Failed*\n\n';
        errorMessage += 'Unable to scan the email file.\n\n';
        errorMessage += '📊 *Try scanning it on our webpage:*\n';
        errorMessage += '🔗 [Visit SafeNet Scanner](https://your-website.com/email-scanner)';
        
        bot.sendMessage(chatId, errorMessage, {
            parse_mode: 'Markdown',
            reply_markup: getBackToMenuKeyboard(),
            disable_web_page_preview: false
        });
    }
}
// Handle Ask AI
async function handleAskAI(chatId, question, session) {
    session.chatHistory.push({ role: 'user', content: question });

    // Send typing action
    bot.sendChatAction(chatId, 'typing');

    try {
        const response = await axios.post('https://localhost:5000/api/ask-ai', {
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