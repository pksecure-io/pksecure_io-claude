#!/usr/bin/env node
/**
 * Telegram Account Verification Tool (Unofficial)
 *
 * PURPOSE: Check if a phone number is registered on Telegram
 *
 * ⚠️ CRITICAL WARNINGS:
 * - This uses the Telegram MTProto API (unofficial client implementation)
 * - VIOLATES Telegram Terms of Service for automated lookups
 * - Risk of account/phone number being BANNED
 * - Use ONLY with dedicated investigation phone number (NOT personal)
 * - ONLY for authorized corporate security investigations
 *
 * INTENDED USE CASE:
 * - Corporate security investigations
 * - BEC (Business Email Compromise) fraud investigations
 * - CEO impersonation/phishing attack attribution
 * - Threat actor identification
 * - Must have proper legal/compliance authorization
 *
 * OPERATIONAL SECURITY:
 * - Use dedicated Google Voice or burner number
 * - Do NOT use personal Telegram accounts
 * - Do NOT use company executive phone numbers
 * - Isolate this tool on dedicated investigation workstation
 * - Log all usage for compliance/audit
 *
 * SETUP REQUIREMENTS:
 * - Node.js 18+ installed
 * - Dedicated phone number (Google Voice recommended)
 * - Telegram API credentials (api_id and api_hash)
 * - See TELEGRAM_SETUP.md for full instructions
 *
 * Author: Paul Kincaid <paul@pksecure.io>
 * License: Apache-2.0
 * Version: 0.1
 *
 * LEGAL: Obtain written authorization from legal/compliance before use.
 */

const { TelegramClient } = require('telegram');
const { StringSession } = require('telegram/sessions');
const { Api } = require('telegram/tl');
const input = require('input');
const fs = require('fs');
const path = require('path');

// Configuration
const LOG_DIR = path.join(__dirname, '../logs');
const SESSION_FILE = path.join(__dirname, '.telegram_session');
const CONFIG_FILE = path.join(__dirname, '.telegram_config.json');

// Ensure directories exist
if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
}

// Logging function
function log(level, message, data = {}) {
    const timestamp = new Date().toISOString();
    const logEntry = {
        timestamp,
        level,
        message,
        ...data
    };

    console.log(`[${timestamp}] ${level.toUpperCase()}: ${message}`);

    // Append to investigation log
    const logFile = path.join(LOG_DIR, `telegram_investigations_${new Date().toISOString().split('T')[0]}.json`);
    fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n');
}

// Display legal warning
function displayLegalWarning() {
    console.log('\n' + '='.repeat(80));
    console.log('WARNING: UNOFFICIAL TELEGRAM VERIFICATION TOOL');
    console.log('='.repeat(80));
    console.log('\n⚠️  TERMS OF SERVICE CONSIDERATIONS');
    console.log('This tool uses Telegram MTProto API for automated lookups.');
    console.log('Excessive automated use may result in account restrictions.\n');

    console.log('✓  AUTHORIZED USE ONLY');
    console.log('- Corporate security investigations');
    console.log('- BEC/phishing/fraud investigations');
    console.log('- Threat actor attribution');
    console.log('- Must have legal/compliance authorization\n');

    console.log('✗  PROHIBITED USE');
    console.log('- Personal investigations');
    console.log('- Harassment or stalking');
    console.log('- Unauthorized surveillance');
    console.log('- Spam or bulk messaging');
    console.log('- Any use without proper authorization\n');

    console.log('🔒 OPERATIONAL SECURITY');
    console.log('- Use dedicated investigation phone number ONLY');
    console.log('- Do NOT use personal Telegram accounts');
    console.log('- All checks are logged for compliance');
    console.log('- Isolate on dedicated investigation workstation');
    console.log('- Rate limit your checks (wait between lookups)\n');

    console.log('='.repeat(80) + '\n');
}

// Load or create configuration
function loadConfig() {
    if (fs.existsSync(CONFIG_FILE)) {
        const config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
        return config;
    }
    return null;
}

function saveConfig(config) {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
}

// Load or create session
function loadSession() {
    if (fs.existsSync(SESSION_FILE)) {
        return fs.readFileSync(SESSION_FILE, 'utf8');
    }
    return '';
}

function saveSession(sessionString) {
    fs.writeFileSync(SESSION_FILE, sessionString);
}

// Parse phone number to Telegram format
function parsePhoneNumber(phoneNumber) {
    // Remove all non-digit characters
    const cleaned = phoneNumber.replace(/[^\d]/g, '');

    // Telegram expects phone number without + sign
    // Example: +1-555-123-4567 becomes 15551234567
    return cleaned;
}

// Check if phone number is registered on Telegram
async function checkTelegramNumber(client, phoneNumber) {
    try {
        log('info', 'Checking Telegram registration', { phoneNumber });

        const formattedNumber = parsePhoneNumber(phoneNumber);

        // Import contacts to check if number is registered
        // This is a legitimate Telegram API method
        const result = await client.invoke(
            new Api.contacts.ImportContacts({
                contacts: [
                    new Api.InputPhoneContact({
                        clientId: BigInt(Date.now()),
                        phone: formattedNumber,
                        firstName: 'Investigation',
                        lastName: 'Check'
                    })
                ]
            })
        );

        const isRegistered = result.imported && result.imported.length > 0;

        const checkResult = {
            phoneNumber,
            formattedNumber,
            isRegistered,
            timestamp: new Date().toISOString()
        };

        if (isRegistered) {
            log('success', 'Telegram account FOUND', checkResult);

            // Get user details
            const importedUser = result.imported[0];
            const userId = importedUser.userId;

            // Get full user info
            try {
                const users = await client.invoke(
                    new Api.users.GetUsers({
                        id: [userId]
                    })
                );

                if (users && users.length > 0) {
                    const user = users[0];
                    checkResult.userId = userId.toString();
                    checkResult.username = user.username || null;
                    checkResult.firstName = user.firstName || null;
                    checkResult.lastName = user.lastName || null;
                    checkResult.isBot = user.bot || false;
                    checkResult.isPremium = user.premium || false;
                    checkResult.isVerified = user.verified || false;

                    log('info', 'Retrieved Telegram user details', {
                        username: checkResult.username,
                        firstName: checkResult.firstName,
                        isVerified: checkResult.isVerified
                    });
                }
            } catch (error) {
                log('warn', 'Could not retrieve full user details', {
                    error: error.message
                });
            }

            // Clean up - delete the contact we just imported
            try {
                await client.invoke(
                    new Api.contacts.DeleteContacts({
                        id: [userId]
                    })
                );
            } catch (error) {
                // Ignore deletion errors
            }

        } else {
            log('info', 'Telegram account NOT FOUND', checkResult);
        }

        return checkResult;

    } catch (error) {
        log('error', 'Telegram check failed', {
            phoneNumber,
            error: error.message,
            stack: error.stack
        });
        throw error;
    }
}

// Main function
async function main() {
    displayLegalWarning();

    // Get phone number from command line
    const args = process.argv.slice(2);
    if (args.length === 0) {
        console.error('Usage: node telegram_check.js <phone_number>');
        console.error('Example: node telegram_check.js "+1-555-123-4567"');
        console.error('Example: node telegram_check.js "15551234567"');
        process.exit(1);
    }

    const phoneNumber = args[0];

    // Load configuration
    let config = loadConfig();

    if (!config) {
        console.log('\n⚠️  FIRST-TIME SETUP REQUIRED\n');
        console.log('You need Telegram API credentials (api_id and api_hash).');
        console.log('See TELEGRAM_SETUP.md for instructions on obtaining these.\n');

        const apiId = await input.text('Enter your Telegram API ID: ');
        const apiHash = await input.text('Enter your Telegram API Hash: ');

        config = {
            apiId: parseInt(apiId),
            apiHash: apiHash
        };

        saveConfig(config);
        console.log('\n✓ Configuration saved\n');
    }

    // Prompt for authorization confirmation
    console.log('Do you have written authorization for this investigation? (yes/no)');
    const authorized = await input.text('Authorization confirmed: ');

    if (authorized.toLowerCase() !== 'yes') {
        console.error('\n❌ Authorization not confirmed. Exiting.');
        log('warn', 'Check aborted - no authorization confirmation');
        process.exit(1);
    }

    log('info', 'Starting Telegram check', {
        phoneNumber,
        authorized: true
    });

    // Initialize Telegram client
    console.log('\n🔄 Initializing Telegram client...\n');

    const sessionString = loadSession();
    const stringSession = new StringSession(sessionString);

    const client = new TelegramClient(
        stringSession,
        config.apiId,
        config.apiHash,
        {
            connectionRetries: 5,
        }
    );

    try {
        await client.start({
            phoneNumber: async () => {
                const phone = await input.text('Enter your investigation phone number (Telegram account): ');
                return phone;
            },
            password: async () => {
                const password = await input.text('Enter your 2FA password (if enabled): ', { silent: true });
                return password;
            },
            phoneCode: async () => {
                console.log('\n📱 Telegram will send you a verification code');
                const code = await input.text('Enter the code you received: ');
                return code;
            },
            onError: (err) => {
                console.error('Authentication error:', err);
                log('error', 'Telegram authentication error', { error: err.message });
            },
        });

        console.log('\n✓ Telegram client authenticated\n');
        log('info', 'Telegram client authenticated and ready');

        // Save session
        const session = client.session.save();
        saveSession(session);

        // Perform the check
        const result = await checkTelegramNumber(client, phoneNumber);

        // Display results
        console.log('\n' + '='.repeat(80));
        console.log('TELEGRAM VERIFICATION RESULT');
        console.log('='.repeat(80) + '\n');
        console.log(`Phone Number:     ${result.phoneNumber}`);
        console.log(`Formatted:        ${result.formattedNumber}`);
        console.log(`Telegram Account: ${result.isRegistered ? '✓ REGISTERED' : '✗ NOT FOUND'}`);

        if (result.isRegistered) {
            console.log(`User ID:          ${result.userId || 'Unknown'}`);
            console.log(`Username:         ${result.username ? '@' + result.username : 'Not set'}`);
            console.log(`First Name:       ${result.firstName || 'Unknown'}`);
            console.log(`Last Name:        ${result.lastName || 'Not set'}`);
            console.log(`Verified:         ${result.isVerified ? 'Yes (✓)' : 'No'}`);
            console.log(`Premium:          ${result.isPremium ? 'Yes' : 'No'}`);
            console.log(`Bot:              ${result.isBot ? 'Yes (Bot Account)' : 'No'}`);
        }

        console.log(`Timestamp:        ${result.timestamp}`);
        console.log('\n' + '='.repeat(80) + '\n');

        // Save result to file
        const resultFile = path.join(LOG_DIR, `telegram_result_${Date.now()}.json`);
        fs.writeFileSync(resultFile, JSON.stringify(result, null, 2));
        console.log(`Result saved to: ${resultFile}\n`);

        // Disconnect
        await client.disconnect();
        process.exit(result.isRegistered ? 0 : 2);

    } catch (error) {
        console.error('\n❌ Error during Telegram check:', error.message);
        log('error', 'Fatal error during check', { error: error.message, stack: error.stack });

        try {
            await client.disconnect();
        } catch (e) {
            // Ignore disconnect errors
        }

        process.exit(1);
    }
}

// Handle errors
process.on('unhandledRejection', (error) => {
    console.error('Unhandled error:', error);
    log('error', 'Unhandled rejection', { error: error.message, stack: error.stack });
    process.exit(1);
});

// Run
main().catch(error => {
    console.error('Fatal error:', error);
    log('error', 'Fatal error in main', { error: error.message, stack: error.stack });
    process.exit(1);
});
