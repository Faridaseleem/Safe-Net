// routes/telegramBotRoutes.js
const express = require('express');
const router = express.Router();
const TelegramBot = require('node-telegram-bot-api');
const axios = require('axios');
require('dotenv').config();

// Initialize bot
const token = process.env.TELEGRAM_BOT_TOKEN;
let bot;

if (token) {
    bot = new TelegramBot(token, { polling: true });
    console.log('✅ Telegram bot initialized successfully');
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
    ]);

    // Handle /start command
    bot.onText(/\/start/, (msg) => {
        const chatId = msg.chat.id;
        const userName = msg.from.first_name || 'User';
        
        const welcomeMessage = `🔒 Welcome ${userName} to Cybersecurity Assistant!\n\n` +
            `I can help you with:\n` +
            `• Scanning URLs for threats\n` +
            `• Reporting malicious URLs\n` +
            `• Answering cybersecurity questions\n` +
            `• Cybersecurity education\n\n` +
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
            `3️⃣ *Ask AI* - Ask cybersecurity questions\n` +
            `4️⃣ *Education* - Learn about cybersecurity\n\n` +
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

            case 'education':
                await handleEducation(chatId);
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

    // Handle regular messages
    bot.on('message', async (msg) => {
        // Skip if it's a command
        if (msg.text && msg.text.startsWith('/')) return;

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
                { text: '🤖 Ask AI', callback_data: 'ask_ai' },
                { text: '📚 Education', callback_data: 'education' }
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

// Handle Education
async function handleEducation(chatId) {
    bot.sendChatAction(chatId, 'typing');

    try {
        const response = await axios.get('http://localhost:5000/api/education/phishing');
        
        let eduMessage = '📚 *Cybersecurity Education*\n\n';
        
        if (response.data.title) {
            eduMessage += `*${response.data.title}*\n\n`;
        }
        
        if (response.data.content) {
            // Truncate if too long
            const content = response.data.content.substring(0, 3000);
            eduMessage += content;
            if (response.data.content.length > 3000) {
                eduMessage += '\n\n_[Content truncated]_';
            }
        } else {
            eduMessage += '```\n' + JSON.stringify(response.data, null, 2) + '\n```';
        }

        bot.sendMessage(chatId, eduMessage, {
            parse_mode: 'Markdown',
            reply_markup: getBackToMenuKeyboard()
        });

    } catch (error) {
        console.error('Error:', error);
        bot.sendMessage(chatId, '❌ Error loading education content.', {
            reply_markup: getBackToMenuKeyboard()
        });
    }
}

// API endpoint to get bot info
router.get('/bot-info', (req, res) => {
    if (bot) {
        bot.getMe().then(info => {
            res.json({
                success: true,
                botInfo: info,
                botLink: `https://t.me/${info.username}`
            });
        }).catch(error => {
            res.status(500).json({ success: false, error: error.message });
        });
    } else {
        res.status(503).json({ success: false, error: 'Bot not initialized' });
    }
});

module.exports = router;