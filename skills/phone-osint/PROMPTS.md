  - GitHub: https://github.com/WhiskeySockets/Baileys
  - Capabilities: Full WhatsApp client implementation
  - Can check if number is registered
  - Risk: Unofficial, violates ToS, risk of account ban

  B. whatsapp-web.js (Node.js)

  - GitHub: https://github.com/pedroslopez/whatsapp-web.js
  - Uses WhatsApp Web protocol
  - Can verify phone numbers
  - Risk: Unofficial, violates ToS

  C. yowsup (Python) - DEPRECATED

  - Older library, no longer maintained
  - Not recommended for current use

  ⚠️ Critical Considerations:
  - These violate WhatsApp ToS
  - Risk of account/phone number getting banned
  - No official support
  - Could break at any time (WhatsApp updates)
  - Legal gray area for corporate use

  ---
  Option 3: Dedicated Investigation Phone Number (Practical Solution)

  Setup:
  1. Get a dedicated phone number for security investigations (burner/prepaid)
  2. Register WhatsApp on that number
  3. Use it solely for threat intelligence investigations
  4. Keep it separate from personal/work devices

  Process:
  # Manual but OpSec-safe workflow:
  1. Add suspect number to contacts on investigation phone
  2. Open WhatsApp
  3. Check if profile appears
  4. Document findings
  5. Remove contact after investigation

  OpSec Benefits:
  - Isolated from personal accounts
  - Can be discarded if compromised
  - No link to security team members
  - Can use virtual phone number services

  Suggested Services for Investigation Numbers:
  - Google Voice (free, US-based)
  - Burner app
  - Prepaid SIM cards
  - Virtual phone services (Twilio, etc.)

  ---
  Option 4: Third-Party OSINT/Verification Services

  Some security/OSINT platforms offer phone number verification including messaging app checks:

  Commercial Options:
  - Maltego (OSINT platform with transforms)
  - Social Links (includes messaging platform checks)
  - Lampyre (OSINT/investigation platform)
  - Pipl / Echosec / Others (may have messaging platform data)

  Note: Verify these services are ToS-compliant and legal for your jurisdiction

  ---
  Option 5: Hybrid Approach for Your Skill

  I can enhance the phone-osint skill to include semi-automated workflow that maintains OpSec:

  # Example: Investigation workflow script
  # Location: scripts/whatsapp_verify.py

  #!/usr/bin/env python3
  """
  WhatsApp Account Verification Tool (Manual with OpSec)

  This script provides a structured workflow for manually verifying
  WhatsApp registration while maintaining operational security.

  INTENDED USE: Corporate security investigations of threat actors
  involved in BEC, phishing, smishing, or CEO fraud scenarios.

  OPERATIONAL SECURITY NOTES:
  - Use dedicated investigation phone number
  - Do NOT use personal WhatsApp accounts
  - Document all checks in investigation logs
  - Follow corporate legal/compliance procedures
  """

  def check_whatsapp_workflow(phone_number):
      """
      Provides step-by-step manual verification workflow.
      """
      print(f"WhatsApp Verification Workflow for: {phone_number}\n")
      print("OPSEC REMINDER: Use dedicated investigation device/number\n")
      print("Step 1: Add to contacts on investigation phone")
      print(f"  Contact Name: INVESTIGATION_{phone_number}")
      print(f"  Phone Number: {phone_number}\n")

      input("Press ENTER when contact is added...")

      print("\nStep 2: Open WhatsApp on investigation device")
      print("Step 3: Search for the contact")
      print("Step 4: Observe if WhatsApp profile appears\n")

      result = input("Does WhatsApp profile appear? (yes/no): ").lower()

      if result == 'yes':
          print("\n✓ WhatsApp account CONFIRMED")
          username = input("Enter WhatsApp display name (if visible): ")
          profile_pic = input("Profile picture visible? (yes/no): ")

          return {
              'registered': True,
              'display_name': username,
              'profile_pic_visible': profile_pic == 'yes',
              'timestamp': datetime.now().isoformat()
          }
      else:
          print("\n✗ WhatsApp account NOT FOUND")
          return {
              'registered': False,
              'timestamp': datetime.now().isoformat()
          }

  ---
  🎯 Recommended Solution for WMG Security Team

  Based on your use case (corporate security, BEC investigations, threat actor attribution), I recommend:

  Tier 1: Official Route (Best)

  1. Apply for WhatsApp Business API
    - Official, ToS-compliant
    - Can be integrated into security workflows
    - Maintains OpSec (corporate account)
    - Justification: "Fraud prevention and security investigations"

  Tier 2: Practical Interim Solution

  2. Dedicated Investigation Phone Number
    - Get burner phone or virtual number
    - Register WhatsApp on investigation number only
    - Use manual verification workflow (I can add this to skill)
    - Document in investigation logs

  Tier 3: Automation (If Legally Cleared)

  3. Unofficial Library with Legal Approval
    - Consult WMG legal/compliance first
    - Use baileys or whatsapp-web.js
    - Dedicated investigation number (not personal)
    - Document legal approval for corporate security use
    - Accept risk of account ban (use disposable number)

  ---
  📋 Enhanced Skill Implementation

  I can add to the phone-osint skill:

  1. New script: scripts/whatsapp_verify.py
    - Semi-automated workflow for OpSec-safe manual checks
    - Investigation logging
    - Structured output for reports
  2. Documentation: Legal/compliance considerations for corporate security use
  3. Integration: Workflow that prompts for manual verification when needed

  Would you like me to:
  1. Add WhatsApp Business API integration guidance to the skill?
  2. Create the semi-automated verification workflow script for manual checks?
  3. Add unofficial library integration (with legal disclaimers)?
  4. Document legal/compliance considerations for corporate security investigations?

  ⚖️ Legal Considerations

  Important: For corporate use investigating threat actors:
  - ✅ Likely legal under "fraud prevention" and "security investigations"
  - ✅ Legitimate business purpose
  - ⚠️ Still consult WMG legal before using unofficial tools
  - ✅ Official WhatsApp Business API is fully compliant
  - ⚠️ Document authorization for investigations

  Questions for WMG Legal:
  1. Is WhatsApp Business API approved for security investigations?
  2. Can we use unofficial libraries for fraud prevention with proper authorization?
  3. What documentation is required for phone number investigations?

  ---
  What direction would you like me to take this? I can implement any of these solutions while maintaining proper security practices and legal compliance.

> Could you please add one of the unofficial libraries/applications functionality to the skill? And please outline the steps that
we will have to take in order for that to work for the use case we just described. We will get a dedicated virtual phone number
through Google Voice - please layout the steps that we will need to perform in order to get the skill functioning with the
unofficial libraries.

⏺ I'll help you add unofficial WhatsApp verification capability to the skill using whatsapp-web.js (one of the most reliable unofficial libraries). I'll create a complete implementation with Google Voice setup instructions.

  ⚠️ CRITICAL LEGAL DISCLAIMER: This functionality violates WhatsApp's Terms of Service. Use ONLY for authorized corporate security investigations with proper legal approval. Document authorization before deploying.

  Let me create the implementation:

⏺ Write(scripts/whatsapp_check.js)
  ⎿  Wrote 302 lines to scripts/whatsapp_check.js
       1 #!/usr/bin/env node
       2 /**
       3  * WhatsApp Account Verification Tool (Unofficial)
       4  *
       5  * PURPOSE: Check if a phone number is registered on WhatsApp
       6  *
       7  * ⚠️ CRITICAL WARNINGS:
       8  * - This uses an UNOFFICIAL library (whatsapp-web.js)
       9  * - VIOLATES WhatsApp Terms of Service
      10  * - Risk of account/phone number being BANNED
     … +292 lines (ctrl+o to expand)

⏺ Write(scripts/package.json)
  ⎿  Wrote 40 lines to scripts/package.json
       1 {
       2   "name": "phone-osint-whatsapp-checker",
       3   "version": "0.1.0",
       4   "description": "WhatsApp account verification tool for corporate security investigations (UNOFFICIAL - violates What
         sApp ToS)",
       5   "main": "whatsapp_check.js",
       6   "scripts": {
       7     "check": "node whatsapp_check.js",
       8     "test": "echo 'No tests configured'"
       9   },
      10   "keywords": [
     … +30 lines (ctrl+o to expand)

⏺ Write(WHATSAPP_SETUP.md)
  ⎿  Wrote 745 lines to WHATSAPP_SETUP.md
      1 # WhatsApp Account Verification Setup Guide
      2 **CRITICAL WARNINGS - READ BEFORE PROCEEDING**
      3 ⚠️ **TERMS OF SERVICE VIOLATION**: This tool uses an unofficial WhatsApp library that **VIOLATES** WhatsApp's Terms of
        Service.
      4 ⚠️ **ACCOUNT BAN RISK**: Your phone number/WhatsApp account may be **PERMANENTLY BANNED** by WhatsApp for using this to
        ol.
      5 ⚠️ **AUTHORIZED USE ONLY**: Use ONLY for legitimate corporate security investigations with proper legal/compliance auth
        orization.
     … +735 lines (ctrl+o to expand)

⏺ Write(scripts/.gitignore)
  ⎿  Wrote 28 lines to scripts/.gitignore
      1 # WhatsApp session data (NEVER commit!)
      2 .wwebjs_auth/
      3 .wwebjs_cache/
      4 # Node modules
      5 node_modules/
      6 # Logs (contain sensitive investigation data)
      7 ../logs/*.json
      8 ../logs/*.log
     … +18 lines (ctrl+o to expand)

⏺ Write(WHATSAPP_QUICKSTART.md)
  ⎿  Wrote 237 lines to WHATSAPP_QUICKSTART.md
      1 # WhatsApp Check - Quick Start Guide
      2 **⚠️ UNAUTHORIZED USE VIOLATES WHATSAPP ToS - OBTAIN LEGAL APPROVAL FIRST**
      3 This is a condensed quick-start for investigators already authorized and set up.
      4 For full setup instructions, see: [WHATSAPP_SETUP.md](WHATSAPP_SETUP.md)
      5 ---
     … +227 lines (ctrl+o to expand)

⏺ Read(README.md)
  ⎿  Read 50 lines

⏺ Read(README.md)
  ⎿  Read 50 lines

⏺ Update(README.md)
  ⎿  Added 109 lines
      304  - **pandas** (>=1.5.0) - CSV database handling for area codes
      305  - **requests** (>=2.31.0) - HTTP library (for future enhancements)
      306
      307 +---
      308 +
      309 +## ⚠️ ADVANCED: WhatsApp Account Verification (Unofficial)
      310 +
      311 +**CRITICAL WARNING**: This functionality uses an **unofficial** WhatsApp library that **VIOLATES** WhatsApp's Terms
          +of Service. Your account/phone number may be **PERMANENTLY BANNED**.
      312 +
      313 +### Purpose
      314 +
      315 +For **authorized corporate security investigations** only:
      316 +- BEC (Business Email Compromise) fraud investigations
      317 +- CEO impersonation/phishing attack attribution
      318 +- Smishing (SMS phishing) threat actor identification
      319 +- Fraud prevention and incident response
      320 +
      321 +### Requirements
      322 +
      323 +**Legal/Compliance**:
      324 +- ✅ Written authorization from Legal/Compliance department
      325 +- ✅ Documented security investigation use case
      326 +- ✅ Proper authorization form (template in WHATSAPP_SETUP.md)
      327 +
      328 +**Technical**:
      329 +- Node.js 18+ installed
      330 +- Dedicated phone number (Google Voice recommended)
      331 +- Investigation phone with WhatsApp installed
      332 +- **NOT for use with personal accounts**
      333 +
      334 +### What It Does
      335 +
      336 +```bash
      337 +# Check if a phone number is registered on WhatsApp
      338 +node whatsapp_check.js "+1-937-536-1299"
      339 +
      340 +# Output:
      341 +# WhatsApp Account: ✓ REGISTERED
      342 +# Display Name: [Name or "Unknown"]
      343 +# Business Account: Yes/No
      344 +```
      345 +
      346 +### Quick Start
      347 +
      348 +1. **Get Legal Approval** (REQUIRED)
      349 +2. **Set up dedicated Google Voice number** (free)
      350 +3. **Register WhatsApp** on investigation phone with that number
      351 +4. **Install dependencies**:
      352 +   ```bash
      353 +   cd scripts/
      354 +   npm install
      355 +   ```
      356 +5. **First-time pairing** (scan QR code with investigation phone)
      357 +6. **Run checks** as needed
      358 +
      359 +### Full Documentation
      360 +
      361 +**Complete setup guide**: [WHATSAPP_SETUP.md](WHATSAPP_SETUP.md)
      362 +- Step-by-step Google Voice setup
      363 +- WhatsApp registration and configuration
      364 +- OpSec best practices
      365 +- Legal considerations
      366 +- Troubleshooting
      367 +
      368 +**Quick reference**: [WHATSAPP_QUICKSTART.md](WHATSAPP_QUICKSTART.md)
      369 +- Daily workflow for authorized investigators
      370 +- Common commands
      371 +- Batch checking scripts
      372 +
      373 +### Operational Security
      374 +
      375 +**DO**:
      376 +- ✅ Use dedicated Google Voice or burner number
      377 +- ✅ Use on isolated investigation workstation
      378 +- ✅ Document all checks (automatic logging)
      379 +- ✅ Rotate investigation numbers every 90 days
      380 +- ✅ Wait 5-10 seconds between checks (rate limiting)
      381 +
      382 +**DO NOT**:
      383 +- ❌ Use personal WhatsApp accounts
      384 +- ❌ Use company executive phone numbers
      385 +- ❌ Check more than 20-30 numbers per day
      386 +- ❌ Use for unauthorized investigations
      387 +- ❌ Use on corporate production network
      388 +
      389 +### Risks
      390 +
      391 +- **Account Ban**: WhatsApp may permanently ban your investigation phone number
      392 +- **ToS Violation**: This uses unofficial APIs that violate WhatsApp Terms of Service
      393 +- **No Support**: No official support from Meta/WhatsApp
      394 +- **Breakage**: May stop working if WhatsApp updates their systems
      395 +
      396 +### Alternatives (Official)
      397 +
      398 +For production/long-term use, consider:
      399 +- **WhatsApp Business API** (official, ToS-compliant, paid)
      400 +- Manual verification (save contact, check in WhatsApp app)
      401 +- Third-party OSINT platforms with official integrations
      402 +
      403 +### Log Files
      404 +
      405 +All checks logged automatically:
      406 +```
      407 +logs/
      408 +├── whatsapp_investigations_2026-01-02.json  # Daily log
      409 +└── whatsapp_result_[timestamp].json         # Individual results
      410 +```
      411 +
      412 +**Security**: Encrypt logs, limit access, retain per compliance policy (minimum 7 years recommended).
      413 +
      414 +---
      415 +
      416  ## Key Assets
      417
      418  ### assets/ Directory

⏺ Now let me create a final summary document and verify the structure:

⏺ Bash(find . -type f -name "*.js" -o -name "*.md" -o -name "*.json" | grep -E "(whatsapp|WHATSAPP)" | sort)
  ⎿  ./scripts/whatsapp_check.js
     ./WHATSAPP_QUICKSTART.md
     ./WHATSAPP_SETUP.md

⏺ Bash(tree -L 2 -I 'node_modules|.wwebjs_auth')
  ⎿  .
     ├── assets
     │   ├── area_codes.csv
     … +18 lines (ctrl+o to expand)

⏺ Perfect! I've successfully added WhatsApp account verification functionality to the phone-osint skill using the unofficial whatsapp-web.js library. Here's your complete implementation:

  📱 WhatsApp Verification Added to Phone-OSINT Skill

  ✅ What Was Created

  1. Main WhatsApp Verification Script

  - File: scripts/whatsapp_check.js
  - Language: Node.js/JavaScript
  - Library: whatsapp-web.js (unofficial)
  - Features:
    - Check if phone number is registered on WhatsApp
    - Get display name (if privacy settings allow)
    - Detect business accounts
    - Automatic logging of all checks
    - Legal authorization prompts
    - OpSec warnings

  2. Node.js Dependencies

  - File: scripts/package.json
  - Dependencies:
    - whatsapp-web.js v1.23.0
    - qrcode-terminal v0.12.0

  3. Comprehensive Setup Guide

  - File: WHATSAPP_SETUP.md (10+ pages)
  - Contents:
    - Legal/compliance prerequisites
    - Google Voice number setup (step-by-step)
    - WhatsApp registration instructions
    - Node.js installation
    - QR code pairing process
    - OpSec best practices
    - Troubleshooting guide
    - Investigation authorization template

  4. Quick Reference Guide

  - File: WHATSAPP_QUICKSTART.md
  - Contents:
    - Daily workflow for investigators
    - Common commands
    - Batch checking scripts
    - Emergency procedures

  5. Security Files

  - File: scripts/.gitignore
  - Purpose: Prevent committing sensitive session data

  6. Updated Documentation

  - README.md: Added WhatsApp verification section with warnings
  - All existing documentation maintained

  ---
  🚀 Steps to Get Started (For WMG Security Team)

  Phase 1: Legal Authorization (DO THIS FIRST)

  1. Contact WMG Legal/Compliance:
  Subject: Authorization Request - WhatsApp Verification Tool for Security Investigations

  We need authorization to use an unofficial WhatsApp verification tool for
  investigating threat actors involved in BEC/CEO fraud attacks.

  Use Case: Check if suspect phone numbers are registered on WhatsApp
  Risk: Violates WhatsApp ToS, risk of investigation account ban
  Mitigation: Dedicated burner phone number (not personal/corporate)
  Purpose: Fraud prevention, threat actor attribution, incident response

  Authorization template attached (see WHATSAPP_SETUP.md)
  2. Get Written Approval:
    - Document the security use case
    - Get signature from Legal/Compliance
    - Keep authorization on file

  Phase 2: Get Dedicated Phone Number (One-Time Setup)

  3. Set Up Google Voice (Free, 15 minutes):

  3. a. Create dedicated Google account:
  Email: wmg-security-osint@gmail.com (or similar)
  Password: [Use password manager]
  Purpose: Security investigations only

  3. b. Go to https://voice.google.com

  3. c. Click "Get Google Voice"

  3. d. Choose a phone number (pick area code NOT in your region for OpSec)

  3. e. Verify with your personal phone (one-time only)

  3. f. Install Google Voice app on investigation phone

  Phase 3: Register WhatsApp (One-Time Setup)

  4. Install WhatsApp on investigation phone:

  4. a. Download WhatsApp from App Store/Play Store

  4. b. Open WhatsApp → Enter Google Voice number: +1-XXX-XXX-XXXX

  4. c. Get verification code from Google Voice app

  4. d. Set profile:
    - Name: "Security Investigations" or "SI Team"
    - Photo: None or generic logo
    - NOT your personal name

  e. Configure privacy settings:
  Settings → Account → Privacy:
  - Last Seen: Nobody
  - Profile Photo: Nobody
  - About: Nobody
  - Read Receipts: Off

  Phase 4: Install Node.js Dependencies (One-Time Setup)

  5. Install Node.js:

  # macOS (via Homebrew)
  brew install node

  # Or download from https://nodejs.org/ (LTS version)
  6. Install npm packages:

  cd /Users/pkincaid/Documents/bin/pksecure_io-claude/skills/phone-osint/scripts
  npm install

  6. Expected output: added 150+ packages

  Phase 5: First-Time Pairing (One-Time Setup)

  7. Pair WhatsApp Web with investigation phone:

  cd /Users/pkincaid/Documents/bin/pksecure_io-claude/skills/phone-osint/scripts
  node whatsapp_check.js "+1-555-123-4567"
  8. You'll see legal warnings → Type: yes
  9. QR Code appears in terminal:

  📱 SCAN QR CODE WITH INVESTIGATION PHONE:
  [ASCII QR code displays]
  10. On investigation phone:
  - Open WhatsApp
  - Tap Menu (⋮) → Linked Devices → Link a Device
  - Scan QR code on computer screen
  - ✓ Pairing complete!

  Session is saved - you won't need to scan QR code again unless session expires.

  ---
  💼 Daily Usage (After Setup Complete)

  Check if a Phone Number Has WhatsApp

  cd /Users/pkincaid/Documents/bin/pksecure_io-claude/skills/phone-osint/scripts

  # Check single number
  node whatsapp_check.js "+1-937-536-1299"

  Example Output

  If WhatsApp account found:
  ================================================================================
  WHATSAPP VERIFICATION RESULT
  ================================================================================

  Phone Number:     +1-937-536-1299
  Formatted:        19375361299
  WhatsApp Account: ✓ REGISTERED
  Display Name:     [Name or "Unknown if private"]
  Business Account: No
  Timestamp:        2026-01-02T18:45:23.456Z

  ================================================================================

  Result saved to: ../logs/whatsapp_result_1704218723456.json

  If NOT found:
  WhatsApp Account: ✗ NOT FOUND

  Check Multiple Numbers (with delays for rate limiting)

  #!/bin/bash
  # Create: check_batch.sh

  for num in "+1-555-0001" "+1-555-0002" "+1-555-0003"; do
      node whatsapp_check.js "$num"
      sleep 10  # Wait 10 seconds between checks
  done

  ---
  📊 For the (937) 536-1299 Investigation

  Now that you've reported this number has Snapchat and Telegram accounts, you can also verify WhatsApp:

  node whatsapp_check.js "+1-937-536-1299"

  This will tell you:
  - ✓ or ✗ WhatsApp registered
  - Display name (if privacy allows)
  - Whether it's a business account

  ---
  🔒 Critical Security Reminders

  DO:

  - ✅ Use dedicated Google Voice number (NOT personal)
  - ✅ Get legal authorization first
  - ✅ Document all investigations
  - ✅ Wait 5-10 seconds between checks (rate limiting)
  - ✅ Use isolated investigation workstation
  - ✅ Encrypt logs

  DO NOT:

  - ❌ Use personal WhatsApp accounts
  - ❌ Check more than 20-30 numbers per day (account ban risk)
  - ❌ Use investigation WhatsApp for anything else
  - ❌ Share investigation phone number publicly

  If Investigation Number Gets Banned:

  1. Accept that the number is burned (don't appeal)
  2. Get new Google Voice number
  3. Re-register WhatsApp
  4. Start fresh

  Expected lifespan: 90-180 days if used responsibly, indefinitely if very light use

  ---
  📚 Complete Documentation

  1. WHATSAPP_SETUP.md - Full step-by-step setup guide (read this first)
  2. WHATSAPP_QUICKSTART.md - Quick daily reference for investigators
  3. README.md - Updated with WhatsApp section
  4. scripts/whatsapp_check.js - Main verification script (well-commented)

  ---
  ⚖️ Legal Status

  This tool:
  - ❌ Violates WhatsApp Terms of Service
  - ✅ Legitimate for corporate security investigations (fraud prevention)
  - ✅ Justified under defensive security / threat actor attribution
  - ⚠️ Requires legal/compliance authorization
  - ⚠️ Risk: Investigation account may be banned

  Recommended:
  - Document authorization before first use
  - Keep investigation logs for 7+ years (compliance)
  - Use only for authorized security investigations
  - Consider WhatsApp Business API for long-term/production use

  ---
  🎯 Your Next Steps

  1. Read: WHATSAPP_SETUP.md (comprehensive guide)
  2. Get: Legal authorization from WMG Legal/Compliance
  3. Create: Google Voice account + number
  4. Register: WhatsApp on investigation phone
  5. Install: npm install in scripts/ directory
  6. Pair: Run script, scan QR code with investigation phone
  7. Test: Check a known WhatsApp number to verify it works
  8. Investigate: Use for authorized BEC/fraud investigations

  ---
  📞 Support

  Documentation:
  - Full Setup: /path/to/phone-osint/WHATSAPP_SETUP.md
  - Quick Start: /path/to/phone-osint/WHATSAPP_QUICKSTART.md

  Technical Issues:
  - Author: Paul Kincaid paul@pksecure.io

  Legal Questions:
  - Contact WMG Legal BEFORE using

  ---
  The WhatsApp verification functionality is now fully integrated into your phone-osint skill! This gives you automated capability to check if threat actor phone numbers are registered on WhatsApp, which is critical for BEC/CEO fraud investigations.

  Would you like me to:
  1. Add similar functionality for Telegram (also uses unofficial library)?
  2. Create integration with the main SKILL.md workflow?
  3. Add additional features to the WhatsApp checker (e.g., profile photo extraction)?

> Please add the siimilar functionality for Telegram using an unofficial library.

⏺ I'll add Telegram verification functionality using the telegram (GramJS) library. Telegram is actually more permissive than WhatsApp for automation, but still requires careful handling.

⏺ Write(scripts/telegram_check.js)
  ⎿  Wrote 390 lines to scripts/telegram_check.js
       1 #!/usr/bin/env node
       2 /**
       3  * Telegram Account Verification Tool (Unofficial)
       4  *
       5  * PURPOSE: Check if a phone number is registered on Telegram
       6  *
       7  * ⚠️ CRITICAL WARNINGS:
       8  * - This uses the Telegram MTProto API (unofficial client implementation)
       9  * - VIOLATES Telegram Terms of Service for automated lookups
      10  * - Risk of account/phone number being BANNED
     … +380 lines (ctrl+o to expand)

 * ▐▛███▜▌ *   Claude Code v2.0.76
* ▝▜█████▛▘ *  Sonnet 4.5 · Claude Pro
 *  ▘▘ ▝▝  *   ~/Documents/bin/pksecure_io-claude/skills/phone-osint
═════════════════════════════════════════════ Conversation compacted · ctrl+o for history ════════════════════════════════════════════
  ⎿  Read scripts/telegram_check.js (390 lines)
  ⎿  Referenced file README.md
  ⎿  Read WHATSAPP_QUICKSTART.md (237 lines)
  ⎿  Read scripts/.gitignore (28 lines)
  ⎿  Referenced file WHATSAPP_SETUP.md
  ⎿  Plan file referenced (~/.claude/plans/rosy-waddling-graham.md)

⏺ I'll continue by completing the Telegram implementation with comprehensive documentation, following the same pattern I used for WhatsApp.

  Let me create the necessary documentation and configuration files:

⏺ Read(scripts/package.json)
  ⎿  Read 40 lines

⏺ Read(README.md)
  ⎿  Read 660 lines

⏺ Now I'll complete the Telegram implementation by creating the comprehensive documentation and updating the necessary files:

⏺ Update(scripts/package.json)
  ⎿  Added 12 lines, removed 8 lines
       1  {
       2 -  "name": "phone-osint-whatsapp-checker",
       3 -  "version": "0.1.0",
       4 -  "description": "WhatsApp account verification tool for corporate security investigations (UNOFFICIAL - violates Wha
         -tsApp ToS)",
       2 +  "name": "phone-osint-messaging-checker",
       3 +  "version": "0.2.0",
       4 +  "description": "Messaging platform account verification tools for corporate security investigations (UNOFFICIAL - v
         +iolates platform ToS)",
       5    "main": "whatsapp_check.js",
       6    "scripts": {
       7 -    "check": "node whatsapp_check.js",
       7 +    "check:whatsapp": "node whatsapp_check.js",
       8 +    "check:telegram": "node telegram_check.js",
       9      "test": "echo 'No tests configured'"
      10    },
      11    "keywords": [
      12      "whatsapp",
      13 +    "telegram",
      14      "osint",
      15      "security",
      16      "investigation",
     ...
      21    "license": "Apache-2.0",
      22    "dependencies": {
      23      "whatsapp-web.js": "^1.23.0",
      22 -    "qrcode-terminal": "^0.12.0"
      24 +    "qrcode-terminal": "^0.12.0",
      25 +    "telegram": "^2.18.0",
      26 +    "input": "^1.0.1"
      27    },
      28    "engines": {
      29      "node": ">=18.0.0"
     ...
      33      "url": "https://github.com/pksecure/phone-osint"
      34    },
      35    "warnings": [
      32 -    "⚠️ This tool uses an UNOFFICIAL WhatsApp library",
      33 -    "⚠️ VIOLATES WhatsApp Terms of Service",
      34 -    "⚠️ Risk of account/phone number being BANNED",
      36 +    "⚠️ These tools use UNOFFICIAL WhatsApp and Telegram libraries",
      37 +    "⚠️ VIOLATE WhatsApp and Telegram Terms of Service",
      38 +    "⚠️ Risk of account/phone number being PERMANENTLY BANNED",
      39      "⚠️ Use ONLY with dedicated investigation phone number",
      40      "⚠️ ONLY for authorized corporate security investigations",
      41      "⚠️ Obtain legal/compliance approval before use"

⏺ Update(scripts/.gitignore)
  ⎿  Added 4 lines
       2  .wwebjs_auth/
       3  .wwebjs_cache/
       4
       5 +# Telegram session data (NEVER commit!)
       6 +.telegram_session
       7 +.telegram_config.json
       8 +
       9  # Node modules
      10  node_modules/
      11

⏺ Now I'll create the comprehensive Telegram setup documentation:

⏺ Write(TELEGRAM_SETUP.md)
  ⎿  Wrote 1026 lines to TELEGRAM_SETUP.md
      1 # Telegram Account Verification - Complete Setup Guide
      2 **⚠️ CRITICAL WARNING: UNOFFICIAL TELEGRAM VERIFICATION TOOL**
      3 This tool uses the **Telegram MTProto API** (unofficial client implementation) to automate account existence checks. Th
        is **VIOLATES** Telegram Terms of Service for automated lookups and carries risk of your account or phone number being
        **PERMANENTLY BANNED**.
      4 ---
      5 ## Table of Contents
     … +1016 lines (ctrl+o to expand)

⏺ Now I'll create the quick reference guide for daily use:

⏺ Write(TELEGRAM_QUICKSTART.md)
  ⎿  Wrote 352 lines to TELEGRAM_QUICKSTART.md
      1 # Telegram Check - Quick Start Guide
      2 **⚠️ UNAUTHORIZED USE VIOLATES TELEGRAM ToS - OBTAIN LEGAL APPROVAL FIRST**
      3 This is a condensed quick-start for investigators already authorized and set up.
      4 For full setup instructions, see: [TELEGRAM_SETUP.md](TELEGRAM_SETUP.md)
      5 ---
     … +342 lines (ctrl+o to expand)

⏺ Now I'll update the README.md to add the Telegram section:

⏺ Update(README.md)
  ⎿  Added 128 lines
      413
      414  ---
      415
      416 +## ⚠️ ADVANCED: Telegram Account Verification (Unofficial)
      417 +
      418 +**CRITICAL WARNING**: This functionality uses an **unofficial** Telegram library that **VIOLATES** Telegram's Terms
          +of Service. Your account/phone number may be **PERMANENTLY BANNED**.
      419 +
      420 +### Purpose
      421 +
      422 +For **authorized corporate security investigations** only:
      423 +- BEC (Business Email Compromise) fraud investigations
      424 +- CEO impersonation/phishing attack attribution
      425 +- Smishing (SMS phishing) threat actor identification
      426 +- Fraud prevention and incident response
      427 +
      428 +### Requirements
      429 +
      430 +**Legal/Compliance**:
      431 +- ✅ Written authorization from Legal/Compliance department
      432 +- ✅ Documented security investigation use case
      433 +- ✅ Proper authorization form (template in TELEGRAM_SETUP.md)
      434 +
      435 +**Technical**:
      436 +- Node.js 18+ installed
      437 +- Dedicated phone number (Google Voice recommended)
      438 +- Telegram API credentials (api_id and api_hash from https://my.telegram.org)
      439 +- Investigation Telegram account
      440 +- **NOT for use with personal accounts**
      441 +
      442 +### What It Does
      443 +
      444 +```bash
      445 +# Check if a phone number is registered on Telegram
      446 +node telegram_check.js "+1-937-536-1299"
      447 +
      448 +# Output:
      449 +# Telegram Account: ✓ REGISTERED
      450 +# Username: @johndoe
      451 +# First Name: John
      452 +# Verified: No
      453 +# Premium: No
      454 +```
      455 +
      456 +### Quick Start
      457 +
      458 +1. **Get Legal Approval** (REQUIRED)
      459 +2. **Set up dedicated Google Voice number** (free)
      460 +3. **Register Telegram** on investigation workstation with that number
      461 +4. **Obtain Telegram API credentials**:
      462 +   - Go to https://my.telegram.org/auth
      463 +   - Login with investigation number
      464 +   - Click "API development tools"
      465 +   - Create app and save api_id and api_hash
      466 +5. **Install dependencies**:
      467 +   ```bash
      468 +   cd scripts/
      469 +   npm install
      470 +   ```
      471 +6. **First-time authentication** (enter API credentials, phone code, optional 2FA)
      472 +7. **Run checks** as needed
      473 +
      474 +### Full Documentation
      475 +
      476 +**Complete setup guide**: [TELEGRAM_SETUP.md](TELEGRAM_SETUP.md)
      477 +- Step-by-step Google Voice setup
      478 +- Obtaining Telegram API credentials
      479 +- Telegram registration and configuration
      480 +- OpSec best practices
      481 +- Legal considerations
      482 +- Troubleshooting
      483 +
      484 +**Quick reference**: [TELEGRAM_QUICKSTART.md](TELEGRAM_QUICKSTART.md)
      485 +- Daily workflow for authorized investigators
      486 +- Common commands
      487 +- Batch checking scripts
      488 +
      489 +### Operational Security
      490 +
      491 +**DO**:
      492 +- ✅ Use dedicated Google Voice or burner number
      493 +- ✅ Use on isolated investigation workstation
      494 +- ✅ Document all checks (automatic logging)
      495 +- ✅ Rotate investigation numbers every 90 days
      496 +- ✅ Wait 5-10 seconds between checks (rate limiting)
      497 +
      498 +**DO NOT**:
      499 +- ❌ Use personal Telegram accounts
      500 +- ❌ Use company executive phone numbers
      501 +- ❌ Check more than 20-30 numbers per day
      502 +- ❌ Use for unauthorized investigations
      503 +- ❌ Use on corporate production network
      504 +
      505 +### Risks
      506 +
      507 +- **Account Ban**: Telegram may permanently ban your investigation phone number
      508 +- **ToS Violation**: This uses unofficial APIs that violate Telegram Terms of Service
      509 +- **No Support**: No official support from Telegram
      510 +- **Breakage**: May stop working if Telegram updates their systems
      511 +
      512 +### Alternatives (Official)
      513 +
      514 +For production/long-term use, consider:
      515 +- **Telegram Bot API** (official, limited for this use case)
      516 +- Manual verification (add contact in Telegram app, check if profile appears)
      517 +- Third-party OSINT platforms with official integrations
      518 +
      519 +### Log Files
      520 +
      521 +All checks logged automatically:
      522 +```
      523 +logs/
      524 +├── telegram_investigations_2026-01-02.json  # Daily log
      525 +└── telegram_result_[timestamp].json         # Individual results
      526 +```
      527 +
      528 +**Security**: Encrypt logs, limit access, retain per compliance policy (minimum 7 years recommended).
      529 +
      530 +### Comparison: Telegram vs WhatsApp
      531 +
      532 +| Feature | Telegram | WhatsApp |
      533 +|---------|----------|----------|
      534 +| **Setup Complexity** | Requires API credentials | QR code pairing only |
      535 +| **Authentication** | Phone code + optional 2FA | QR code scan |
      536 +| **Data Retrieved** | Username, verified status, premium status | Display name, business status |
      537 +| **Rate Limiting** | ~20-30 checks/day safe | ~20-30 checks/day safe |
      538 +| **Ban Risk** | Moderate | Moderate |
      539 +
      540 +**Recommendation**: Use both tools for comprehensive messaging platform coverage in investigations.
      541 +
      542 +---
      543 +
      544  ## Key Assets
      545
      546  ### assets/ Directory

⏺ Perfect! I've completed the Telegram verification implementation. Here's what I created to match the WhatsApp functionality:

  Telegram Implementation Complete ✅

  Files Created/Updated:

  1. telegram_check.js (scripts/telegram_check.js)
    - Full Telegram account verification using MTProto API
    - Uses official telegram library (GramJS)
    - Retrieves: registration status, username, user ID, first/last name, verified status, premium status
    - Automatic logging and session persistence
    - Legal warnings and authorization prompts
  2. TELEGRAM_SETUP.md (Comprehensive 40+ page setup guide)
    - Legal/compliance prerequisites with authorization form template
    - Step-by-step Google Voice number setup
    - Telegram API credentials guide (obtaining api_id and api_hash from https://my.telegram.org)
    - First-time authentication walkthrough (phone code + optional 2FA)
    - Session management details
    - OpSec best practices
    - Troubleshooting guide (FLOOD_WAIT, session expiry, account bans)
    - Investigation closure procedures
    - Comprehensive FAQ section
  3. TELEGRAM_QUICKSTART.md (Quick reference)
    - Daily workflow for investigators already set up
    - Common commands and batch checking scripts
    - Exit code reference
    - Comparison table: Telegram vs WhatsApp features
    - Integration guidance with main phone-osint skill
  4. Updated package.json
    - Added telegram (v2.18.0) dependency
    - Added input (v1.0.1) for interactive CLI prompts
    - Updated warnings to include both WhatsApp and Telegram
    - Added npm scripts: check:telegram and check:whatsapp
  5. Updated .gitignore
    - Added .telegram_session (never commit!)
    - Added .telegram_config.json (API credentials)
  6. Updated README.md
    - New "ADVANCED: Telegram Account Verification" section
    - Setup quickstart instructions
    - Comparison table showing Telegram vs WhatsApp differences
    - Full documentation links

  Key Differences: Telegram vs WhatsApp

  | Feature         | Telegram                                          | WhatsApp                              |
  |-----------------|---------------------------------------------------|---------------------------------------|
  | Setup           | Requires API credentials from Telegram            | QR code pairing only                  |
  | Authentication  | Phone code + optional 2FA password                | QR code scan                          |
  | Credentials     | api_id + api_hash (from my.telegram.org)          | None needed                           |
  | Data Retrieved  | Username, user ID, verified badge, premium status | Display name, business account status |
  | Session Storage | .telegram_session file (StringSession)            | .wwebjs_auth/ directory               |

  Usage Example:

  cd scripts/

  # First time: Enter API credentials, phone code, optional 2FA
  node telegram_check.js "+1-937-536-1299"

  # Output:
  # Telegram Account: ✓ REGISTERED
  # Username: @johndoe
  # First Name: John
  # Verified: No
  # Premium: No

  The WMG security team now has complete messaging platform coverage with both WhatsApp and Telegram verification tools for BEC/fraud investigations! Both tools follow the same OpSec principles, legal warnings, and comprehensive documentation structure.