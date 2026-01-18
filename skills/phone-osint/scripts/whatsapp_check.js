#!/usr/bin/env node
/**
 * WhatsApp Account Verification Tool (Unofficial)
 *
 * PURPOSE: Check if a phone number is registered on WhatsApp
 *
 * ⚠️ CRITICAL WARNINGS:
 * - This uses an UNOFFICIAL library (whatsapp-web.js)
 * - VIOLATES WhatsApp Terms of Service
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
 * - Do NOT use personal WhatsApp accounts
 * - Do NOT use company executive phone numbers
 * - Isolate this tool on dedicated investigation workstation
 * - Log all usage for compliance/audit
 *
 * SETUP REQUIREMENTS:
 * - Node.js 18+ installed
 * - Dedicated phone number (Google Voice recommended)
 * - QR code scanner capability (phone camera)
 * - See WHATSAPP_SETUP.md for full instructions
 *
 * Author: Paul Kincaid <paul@pksecure.io>
 * License: Apache-2.0
 * Version: 0.1
 *
 * LEGAL: Obtain written authorization from legal/compliance before use.
 */

const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');
const fs = require('fs');
const path = require('path');

// Configuration
const LOG_DIR = path.join(__dirname, '../logs');
const SESSION_DIR = path.join(__dirname, '../.wwebjs_auth');

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
    const logFile = path.join(LOG_DIR, `whatsapp_investigations_${new Date().toISOString().split('T')[0]}.json`);
    fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n');
}

// Display legal warning
function displayLegalWarning() {
    console.log('\n' + '='.repeat(80));
    console.log('WARNING: UNOFFICIAL WHATSAPP VERIFICATION TOOL');
    console.log('='.repeat(80));
    console.log('\n⚠️  TERMS OF SERVICE VIOLATION');
    console.log('This tool uses an unofficial library that VIOLATES WhatsApp ToS.');
    console.log('Your phone number/account may be BANNED by WhatsApp.\n');

    console.log('✓  AUTHORIZED USE ONLY');
    console.log('- Corporate security investigations');
    console.log('- BEC/phishing/fraud investigations');
    console.log('- Threat actor attribution');
    console.log('- Must have legal/compliance authorization\n');

    console.log('✗  PROHIBITED USE');
    console.log('- Personal investigations');
    console.log('- Harassment or stalking');
    console.log('- Unauthorized surveillance');
    console.log('- Any use without proper authorization\n');

    console.log('🔒 OPERATIONAL SECURITY');
    console.log('- Use dedicated investigation phone number ONLY');
    console.log('- Do NOT use personal WhatsApp accounts');
    console.log('- All checks are logged for compliance');
    console.log('- Isolate on dedicated investigation workstation\n');

    console.log('='.repeat(80) + '\n');
}

// Check if phone number is registered on WhatsApp
async function checkWhatsAppNumber(client, phoneNumber) {
    try {
        log('info', 'Checking WhatsApp registration', { phoneNumber });

        // Format phone number (must be in international format without + or spaces)
        // Example: +1-555-123-4567 becomes 15551234567
        const formattedNumber = phoneNumber.replace(/[^\d]/g, '');

        // Check if number is registered on WhatsApp
        const numberId = `${formattedNumber}@c.us`;
        const isRegistered = await client.isRegisteredUser(numberId);

        const result = {
            phoneNumber,
            formattedNumber,
            isRegistered,
            timestamp: new Date().toISOString()
        };

        if (isRegistered) {
            log('success', 'WhatsApp account FOUND', result);

            // Optionally get contact info (if available)
            try {
                const contact = await client.getContactById(numberId);
                result.displayName = contact.pushname || contact.name || 'Unknown';
                result.isMyContact = contact.isMyContact;
                result.isBusiness = contact.isBusiness;

                log('info', 'Retrieved contact details', {
                    displayName: result.displayName,
                    isBusiness: result.isBusiness
                });
            } catch (error) {
                log('warn', 'Could not retrieve contact details (privacy settings)', {
                    error: error.message
                });
            }
        } else {
            log('info', 'WhatsApp account NOT FOUND', result);
        }

        return result;

    } catch (error) {
        log('error', 'WhatsApp check failed', {
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
        console.error('Usage: node whatsapp_check.js <phone_number>');
        console.error('Example: node whatsapp_check.js "+1-555-123-4567"');
        console.error('Example: node whatsapp_check.js "15551234567"');
        process.exit(1);
    }

    const phoneNumber = args[0];

    // Require confirmation for first-time setup
    if (!fs.existsSync(path.join(SESSION_DIR, 'session'))) {
        console.log('⚠️  FIRST-TIME SETUP REQUIRED\n');
        console.log('You will need to:');
        console.log('1. Scan QR code with your DEDICATED INVESTIGATION phone');
        console.log('2. This will link WhatsApp Web to that phone number');
        console.log('3. The session will be saved for future checks\n');
        console.log('Make sure you are using a dedicated Google Voice or burner number!\n');
    }

    // Prompt for authorization confirmation
    console.log('Do you have written authorization for this investigation? (yes/no)');
    const readline = require('readline').createInterface({
        input: process.stdin,
        output: process.stdout
    });

    const authorized = await new Promise(resolve => {
        readline.question('Authorization confirmed: ', answer => {
            readline.close();
            resolve(answer.toLowerCase() === 'yes');
        });
    });

    if (!authorized) {
        console.error('\n❌ Authorization not confirmed. Exiting.');
        log('warn', 'Check aborted - no authorization confirmation');
        process.exit(1);
    }

    log('info', 'Starting WhatsApp check', {
        phoneNumber,
        authorized: true
    });

    // Initialize WhatsApp client
    console.log('\n🔄 Initializing WhatsApp client...\n');

    const client = new Client({
        authStrategy: new LocalAuth({
            dataPath: SESSION_DIR
        }),
        puppeteer: {
            headless: true,
            args: ['--no-sandbox', '--disable-setuid-sandbox']
        }
    });

    // QR Code event
    client.on('qr', (qr) => {
        console.log('📱 SCAN QR CODE WITH INVESTIGATION PHONE:\n');
        qrcode.generate(qr, { small: true });
        console.log('\nSteps:');
        console.log('1. Open WhatsApp on investigation phone (with dedicated number)');
        console.log('2. Tap Menu (⋮) → Linked Devices → Link a Device');
        console.log('3. Scan the QR code above\n');
        log('info', 'QR code displayed for authentication');
    });

    // Ready event
    client.on('ready', async () => {
        console.log('✓ WhatsApp client ready\n');
        log('info', 'WhatsApp client authenticated and ready');

        try {
            // Perform the check
            const result = await checkWhatsAppNumber(client, phoneNumber);

            // Display results
            console.log('\n' + '='.repeat(80));
            console.log('WHATSAPP VERIFICATION RESULT');
            console.log('='.repeat(80) + '\n');
            console.log(`Phone Number:     ${result.phoneNumber}`);
            console.log(`Formatted:        ${result.formattedNumber}`);
            console.log(`WhatsApp Account: ${result.isRegistered ? '✓ REGISTERED' : '✗ NOT FOUND'}`);

            if (result.isRegistered) {
                console.log(`Display Name:     ${result.displayName || 'Unknown (privacy protected)'}`);
                console.log(`Business Account: ${result.isBusiness ? 'Yes' : 'No'}`);
            }

            console.log(`Timestamp:        ${result.timestamp}`);
            console.log('\n' + '='.repeat(80) + '\n');

            // Save result to file
            const resultFile = path.join(LOG_DIR, `whatsapp_result_${Date.now()}.json`);
            fs.writeFileSync(resultFile, JSON.stringify(result, null, 2));
            console.log(`Result saved to: ${resultFile}\n`);

            // Clean exit
            await client.destroy();
            process.exit(result.isRegistered ? 0 : 2);

        } catch (error) {
            console.error('\n❌ Error during WhatsApp check:', error.message);
            await client.destroy();
            process.exit(1);
        }
    });

    // Authentication failure
    client.on('auth_failure', (msg) => {
        console.error('❌ Authentication failed:', msg);
        log('error', 'WhatsApp authentication failed', { message: msg });
        process.exit(1);
    });

    // Disconnected
    client.on('disconnected', (reason) => {
        console.log('Disconnected:', reason);
        log('info', 'WhatsApp client disconnected', { reason });
    });

    // Initialize client
    client.initialize();
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
