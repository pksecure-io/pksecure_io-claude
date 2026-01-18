# WhatsApp Account Verification Setup Guide

**CRITICAL WARNINGS - READ BEFORE PROCEEDING**

⚠️ **TERMS OF SERVICE VIOLATION**: This tool uses an unofficial WhatsApp library that **VIOLATES** WhatsApp's Terms of Service.

⚠️ **ACCOUNT BAN RISK**: Your phone number/WhatsApp account may be **PERMANENTLY BANNED** by WhatsApp for using this tool.

⚠️ **AUTHORIZED USE ONLY**: Use ONLY for legitimate corporate security investigations with proper legal/compliance authorization.

---

## Table of Contents

1. [Legal & Compliance Prerequisites](#legal--compliance-prerequisites)
2. [Operational Security Considerations](#operational-security-considerations)
3. [Step 1: Get Google Voice Number](#step-1-get-google-voice-number)
4. [Step 2: Install WhatsApp on Investigation Device](#step-2-install-whatsapp-on-investigation-device)
5. [Step 3: Install Node.js Dependencies](#step-3-install-nodejs-dependencies)
6. [Step 4: First-Time Setup & QR Code Pairing](#step-4-first-time-setup--qr-code-pairing)
7. [Step 5: Running Phone Number Checks](#step-5-running-phone-number-checks)
8. [Troubleshooting](#troubleshooting)
9. [Logging & Compliance](#logging--compliance)
10. [Decommissioning](#decommissioning)

---

## Legal & Compliance Prerequisites

**BEFORE PROCEEDING**, you MUST obtain:

### ✅ Required Authorizations

1. **Written Legal Approval** from WMG Legal/Compliance department
   - Document the security investigation use case
   - Specify: BEC/CEO fraud, phishing, smishing investigations
   - Note: Threat actor attribution and fraud prevention

2. **IT Security Approval** for installing unofficial software
   - This tool connects to WhatsApp's servers
   - Uses unofficial API (not supported by Meta)
   - Requires dedicated investigation workstation

3. **Data Privacy/GDPR Compliance Review**
   - Phone number lookups may involve personal data
   - Ensure compliance with applicable privacy laws
   - Document legitimate interest for fraud prevention

### 📋 Documentation Requirements

Create an investigation authorization form that includes:
- Investigation case ID/reference number
- Threat description (BEC, CEO fraud, phishing, etc.)
- Phone numbers to be investigated (suspect threat actor numbers)
- Authorized investigator name(s)
- Legal approval signature
- Date and expiration

**Save template**: `investigation_authorization_template.txt` in your secure docs

---

## Operational Security Considerations

### 🔒 OpSec Best Practices

**DO:**
- ✅ Use dedicated Google Voice or burner number (NOT personal)
- ✅ Use dedicated investigation workstation (isolated from corporate network)
- ✅ Document all investigations in secure log
- ✅ Rotate investigation numbers periodically (every 90 days recommended)
- ✅ Use VPN or isolated network for investigations
- ✅ Limit access to authorized security team members only

**DO NOT:**
- ❌ Use personal WhatsApp accounts
- ❌ Use company executive phone numbers
- ❌ Use from corporate workstations connected to production network
- ❌ Share investigation phone number publicly
- ❌ Use for non-authorized investigations
- ❌ Keep investigation phone linked after completing investigation

### 🎯 Investigation Workflow

```
Threat Detected → Legal Authorization → Setup Investigation Number →
Link WhatsApp → Perform Check → Document Results → Unlink Device →
Archive Logs
```

---

## Step 1: Get Google Voice Number

### Option A: Google Voice (Free, US-based)

**Requirements**:
- Google account (create dedicated one for investigations)
- US-based location (or VPN)
- Existing phone number for verification (can be personal, only used once)

**Steps**:

1. **Create dedicated Google account**
   ```
   Email: wmg-security-investigations@gmail.com (or similar)
   Purpose: Security investigations only
   ```

2. **Go to Google Voice**: https://voice.google.com

3. **Click "Get Google Voice"**

4. **Select a phone number**:
   - Choose area code (preferably NOT your local area code for OpSec)
   - Select a memorable number for your records
   - Example: Choose 650 (California) or 404 (Georgia) if you're not in those areas

5. **Verify with existing phone**:
   - You'll need to verify once with a real phone number
   - Can use personal phone (only used for initial setup)
   - After verification, you can use Google Voice independently

6. **Configure Google Voice**:
   - Settings → Linked numbers → Remove your personal number (after verification)
   - Settings → Voicemail → Set professional greeting or disable
   - Settings → Call forwarding → Disable (handle calls via app only)

7. **Install Google Voice app** on dedicated investigation phone:
   - iOS: https://apps.apple.com/us/app/google-voice/id318698524
   - Android: https://play.google.com/store/apps/details?id=com.google.android.apps.googlevoice

8. **Document the number**:
   ```
   Investigation Number: +1-XXX-XXX-XXXX
   Purpose: WhatsApp verification for security investigations
   Created: YYYY-MM-DD
   Google Account: wmg-security-investigations@gmail.com
   ```

### Option B: Burner/Prepaid Number (Alternative)

If Google Voice doesn't work or you need more isolation:

**Options**:
- Burner app: https://www.burnerapp.com/ (~$5/month)
- Prepaid SIM card (local mobile carrier)
- Virtual phone services: Twilio, Telnyx (more expensive)

**Recommendation**: Google Voice is free and works well for this purpose.

---

## Step 2: Install WhatsApp on Investigation Device

### Choose Your Investigation Device

**Option A: Dedicated Phone (Recommended)**
- Old smartphone repurposed for investigations
- Separate from personal/work devices
- Can be factory reset between investigations

**Option B: Investigation Laptop/Desktop + Phone Companion**
- Laptop runs the Node.js script
- Phone is used only for WhatsApp registration and QR scanning
- Phone can be basic/cheap (just needs WhatsApp app)

### Install WhatsApp

1. **Download WhatsApp** on your investigation phone:
   - iOS: https://apps.apple.com/app/whatsapp-messenger/id310633997
   - Android: https://play.google.com/store/apps/details?id=com.whatsapp

2. **Register WhatsApp with Google Voice number**:

   **Steps**:
   ```
   a. Open WhatsApp app
   b. Tap "Agree and Continue"
   c. Enter your Google Voice number: +1-XXX-XXX-XXXX
   d. Tap "Next"

   e. WhatsApp will send SMS verification code
      - Open Google Voice app to receive the code
      - Check Messages tab in Google Voice
      - Copy the 6-digit code

   f. Enter verification code in WhatsApp

   g. Set profile:
      - Name: "Security Investigations" or "SI Team" (NOT personal name)
      - Profile photo: Optional (use generic/corporate logo or none)

   h. Skip backup (optional - not needed for investigations)
   ```

3. **Verify WhatsApp is working**:
   - You should see WhatsApp home screen
   - Status: "Loading..."
   - You now have a working WhatsApp account on your investigation number

### Important WhatsApp Settings

Configure for OpSec:

```
Settings → Account → Privacy:
- Last Seen: Nobody
- Profile Photo: Nobody (or Contacts only)
- About: Nobody
- Status: Nobody (or Contacts only)
- Read Receipts: Off (optional)
- Groups: My Contacts

Settings → Account → Security:
- Show Security Notifications: On
- Two-Step Verification: Enable (use secure PIN)
```

---

## Step 3: Install Node.js Dependencies

### Prerequisites

1. **Install Node.js** (v18 or higher)

   **macOS** (using Homebrew):
   ```bash
   brew install node
   ```

   **macOS** (direct download):
   - Download from: https://nodejs.org/
   - Choose "LTS" version (currently 20.x)
   - Run installer

   **Linux** (Ubuntu/Debian):
   ```bash
   curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
   sudo apt-get install -y nodejs
   ```

   **Verify installation**:
   ```bash
   node --version  # Should show v18.x or higher
   npm --version   # Should show 9.x or higher
   ```

2. **Navigate to skill scripts directory**:
   ```bash
   cd /Users/pkincaid/Documents/bin/pksecure_io-claude/skills/phone-osint/scripts
   ```

3. **Install npm dependencies**:
   ```bash
   npm install
   ```

   This will install:
   - `whatsapp-web.js` - Unofficial WhatsApp Web client
   - `qrcode-terminal` - QR code display in terminal

   **Expected output**:
   ```
   added 150+ packages in 30s

   ⚠️  Warnings about unofficial library are expected
   ```

### Verify Installation

```bash
node -e "console.log('Node.js is working')"
```

Should output: `Node.js is working`

---

## Step 4: First-Time Setup & QR Code Pairing

### Initial Pairing Process

The first time you run the script, you'll need to pair it with WhatsApp Web.

1. **Run the script for the first time**:

   ```bash
   cd /Users/pkincaid/Documents/bin/pksecure_io-claude/skills/phone-osint/scripts
   node whatsapp_check.js "+1-555-123-4567"
   ```

2. **You'll see legal warnings**:
   ```
   ================================================================================
   WARNING: UNOFFICIAL WHATSAPP VERIFICATION TOOL
   ================================================================================

   ⚠️  TERMS OF SERVICE VIOLATION
   This tool uses an unofficial library that VIOLATES WhatsApp ToS...
   ```

3. **Confirm authorization**:
   ```
   Do you have written authorization for this investigation? (yes/no)
   Authorization confirmed: yes
   ```

4. **QR Code will appear**:

   ```
   📱 SCAN QR CODE WITH INVESTIGATION PHONE:

   █████████████████████████████████████
   ██ ▄▄▄▄▄ █▀ █▀▀██ ▄ ▀▄█ ▄▄▄▄▄ ██
   ██ █   █ █▀ ▀▄▀ █▀█ ▄██ █   █ ██
   ██ █▄▄▄█ █ ▄▀█▀ ▀▀▀▄ ██ █▄▄▄█ ██
   ... (QR code) ...

   Steps:
   1. Open WhatsApp on investigation phone (with dedicated number)
   2. Tap Menu (⋮) → Linked Devices → Link a Device
   3. Scan the QR code above
   ```

5. **On your investigation phone**:

   **Steps**:
   ```
   a. Open WhatsApp
   b. Tap the three dots (⋮) in top right
   c. Select "Linked Devices"
   d. Tap "Link a Device"
   e. WhatsApp will ask for fingerprint/PIN (approve)
   f. Point phone camera at the QR code on your computer screen
   g. Wait for pairing confirmation
   ```

6. **Pairing successful**:
   ```
   ✓ WhatsApp client ready

   🔄 Checking WhatsApp registration for +1-555-123-4567...
   ```

7. **Session saved**:
   - After successful pairing, the session is saved
   - Location: `phone-osint/scripts/.wwebjs_auth/`
   - You won't need to scan QR code again (unless you clear the session)

### Session Management

**Session Location**:
```
phone-osint/scripts/.wwebjs_auth/
└── session/
    ├── Default/
    └── ... (session files)
```

**Session Persistence**:
- Sessions last indefinitely until you log out or WhatsApp disconnects
- If WhatsApp disconnects you, you'll need to re-pair (scan QR again)
- Sessions are device-specific (tied to this computer)

**Clear Session** (when needed):
```bash
rm -rf /Users/pkincaid/Documents/bin/pksecure_io-claude/skills/phone-osint/scripts/.wwebjs_auth
```

---

## Step 5: Running Phone Number Checks

### Basic Usage

Once paired, you can check phone numbers:

```bash
cd /Users/pkincaid/Documents/bin/pksecure_io-claude/skills/phone-osint/scripts

# Check if a number has WhatsApp
node whatsapp_check.js "+1-937-536-1299"
```

### Supported Number Formats

The script accepts multiple formats:

```bash
# International format (preferred)
node whatsapp_check.js "+1-555-123-4567"

# No formatting
node whatsapp_check.js "15551234567"

# With parentheses
node whatsapp_check.js "(555) 123-4567"

# International (non-US)
node whatsapp_check.js "+44 20 7183 8750"
```

### Example Output

**If WhatsApp account found**:
```
================================================================================
WHATSAPP VERIFICATION RESULT
================================================================================

Phone Number:     +1-937-536-1299
Formatted:        19375361299
WhatsApp Account: ✓ REGISTERED
Display Name:     John Doe (or Unknown if privacy protected)
Business Account: No
Timestamp:        2026-01-02T18:45:23.456Z

================================================================================

Result saved to: ../logs/whatsapp_result_1704218723456.json
```

**If WhatsApp account NOT found**:
```
================================================================================
WHATSAPP VERIFICATION RESULT
================================================================================

Phone Number:     +1-555-000-9999
Formatted:        15550009999
WhatsApp Account: ✗ NOT FOUND
Timestamp:        2026-01-02T18:45:23.456Z

================================================================================
```

### Exit Codes

```
0 = WhatsApp account found
2 = WhatsApp account not found
1 = Error occurred
```

Use in shell scripts:
```bash
if node whatsapp_check.js "+1-555-123-4567"; then
    echo "Account exists"
else
    echo "Account not found or error"
fi
```

### Batch Checking

For multiple numbers, create a shell script:

```bash
#!/bin/bash
# check_multiple.sh

NUMBERS=(
    "+1-555-123-4567"
    "+1-555-234-5678"
    "+1-555-345-6789"
)

for number in "${NUMBERS[@]}"; do
    echo "Checking $number..."
    node whatsapp_check.js "$number"
    sleep 5  # Wait 5 seconds between checks (rate limiting)
done
```

**IMPORTANT**: Add delays between checks to avoid triggering WhatsApp anti-spam measures.

---

## Troubleshooting

### Issue: "QR Code Not Displaying"

**Solution**:
- Check terminal supports QR code rendering
- Try a different terminal (iTerm2, Terminal.app, etc.)
- QR code should render as ASCII art

### Issue: "QR Code Expired"

**Solution**:
- QR codes expire after ~60 seconds
- Restart the script to get a new QR code
- Be ready to scan immediately when QR appears

### Issue: "Authentication Failed"

**Possible Causes**:
1. **WhatsApp already linked to 4 devices** (WhatsApp limit)
   - Solution: Unlink an old device in WhatsApp → Linked Devices
2. **Network connectivity issues**
   - Solution: Check internet connection, try again
3. **WhatsApp server issues**
   - Solution: Wait and retry later

### Issue: "Phone Number Not Found" (but you know it has WhatsApp)

**Possible Causes**:
1. **Wrong number format**
   - Ensure international format: +1-555-123-4567
   - Script auto-formats, but double-check
2. **Number recently registered**
   - Wait a few hours, try again
3. **WhatsApp privacy settings**
   - User may have restricted discoverability (rare)

### Issue: "Account Banned" or "Number Disconnected"

**⚠️ This is the risk of using unofficial tools**

**If your investigation WhatsApp account gets banned**:
1. Accept that the investigation number is burned
2. Do NOT try to appeal (reveals unofficial tool use)
3. Get a new Google Voice number
4. Start fresh with new number
5. Document incident in security logs

**Prevention**:
- Don't check too many numbers too quickly (rate limiting)
- Use delays between checks (5-10 seconds minimum)
- Rotate investigation numbers every 90 days
- Don't use the investigation WhatsApp account for anything else

### Issue: "Session Disconnected"

**Solution**:
```bash
# Clear old session
rm -rf .wwebjs_auth/

# Re-run script (will prompt for QR code again)
node whatsapp_check.js "+1-555-123-4567"
```

---

## Logging & Compliance

### Log Files

All checks are automatically logged:

**Location**: `/Users/pkincaid/Documents/bin/pksecure_io-claude/skills/phone-osint/logs/`

**Log Files**:
```
logs/
├── whatsapp_investigations_2026-01-02.json    # Daily investigation log
├── whatsapp_result_1704218723456.json         # Individual result
├── whatsapp_result_1704218788123.json
└── ...
```

### Daily Investigation Log Format

```json
{"timestamp":"2026-01-02T18:45:23.456Z","level":"info","message":"Starting WhatsApp check","phoneNumber":"+1-555-123-4567","authorized":true}
{"timestamp":"2026-01-02T18:45:25.789Z","level":"success","message":"WhatsApp account FOUND","phoneNumber":"+1-555-123-4567","isRegistered":true}
```

### Individual Result File Format

```json
{
  "phoneNumber": "+1-937-536-1299",
  "formattedNumber": "19375361299",
  "isRegistered": true,
  "displayName": "John Doe",
  "isBusiness": false,
  "timestamp": "2026-01-02T18:45:23.456Z"
}
```

### Compliance Requirements

**Retain logs for**:
- Legal compliance: Minimum 7 years (or per company policy)
- Security investigations: Duration of case + retention period

**Log Security**:
- Store logs on secure, access-controlled system
- Encrypt logs at rest (use FileVault, BitLocker, or encrypted volume)
- Limit access to authorized security team only
- Include logs in backup/DR procedures

**Audit Trail**:
- Each check is logged with timestamp
- Includes authorization confirmation
- Links to investigation case ID (add manually if needed)

---

## Decommissioning

### When Investigation is Complete

1. **Unlink WhatsApp Web**:
   ```
   On investigation phone:
   WhatsApp → Settings → Linked Devices
   → Find the linked computer → Tap → "Log Out"
   ```

2. **Clear local session**:
   ```bash
   cd /Users/pkincaid/Documents/bin/pksecure_io-claude/skills/phone-osint/scripts
   rm -rf .wwebjs_auth/
   ```

3. **Archive logs** (if investigation closed):
   ```bash
   # Move to secure archive
   mv logs/ ~/secure_archives/investigations/case-12345/whatsapp-logs/
   ```

4. **Decommission Google Voice number** (optional):
   - If number was compromised or investigation complete
   - Google Voice → Settings → Delete number
   - Or keep for future investigations (recommended)

### Rotating Investigation Numbers

**Recommended**: Every 90 days or after major investigation

1. Get new Google Voice number
2. Register new WhatsApp account
3. Update documentation
4. Decommission old number

---

## Security Checklist

Before first use:

- [ ] Legal/compliance authorization obtained
- [ ] Dedicated Google Voice number created
- [ ] WhatsApp registered on investigation phone
- [ ] WhatsApp privacy settings configured
- [ ] Node.js and dependencies installed
- [ ] QR code pairing completed successfully
- [ ] Test check performed (known WhatsApp number)
- [ ] Logs directory secured and backed up
- [ ] Investigation authorization form template created
- [ ] Team trained on OpSec procedures

Before each investigation:

- [ ] Investigation authorization documented
- [ ] Case ID assigned
- [ ] Phone numbers validated (formatted correctly)
- [ ] Investigation phone charged and ready
- [ ] VPN connected (if using)
- [ ] Results will be logged and archived

After each investigation:

- [ ] Results documented in case file
- [ ] Logs archived securely
- [ ] WhatsApp Web unlinked (if investigation complete)
- [ ] Investigation phone secured

---

## Support & Questions

**For WMG Security Team**:
- Internal documentation: [Add your internal wiki link]
- Security team Slack: #security-investigations
- On-call security: [Add contact]

**Tool Issues**:
- Author: Paul Kincaid <paul@pksecure.io>
- Skill repository: [Add repo link if applicable]

**Legal/Compliance Questions**:
- Contact WMG Legal before use
- Privacy/GDPR questions: [Add contact]

---

## Appendix: Legal Template

### Investigation Authorization Form

```
WHATSAPP INVESTIGATION AUTHORIZATION

Case ID: ___________________________
Date: _______________________________
Investigator: ________________________

THREAT DESCRIPTION:
[ ] BEC (Business Email Compromise)
[ ] CEO Fraud / Executive Impersonation
[ ] Phishing Attack
[ ] Smishing (SMS Phishing)
[ ] Other: _________________________

PHONE NUMBERS TO INVESTIGATE:
1. _________________________________
2. _________________________________
3. _________________________________

JUSTIFICATION:
These phone numbers are suspected to be used by threat actors in
[describe attack/incident]. Investigation is necessary for:
- Threat actor attribution
- Fraud prevention
- Incident response
- Industry information sharing

LEGAL AUTHORIZATION:
I confirm that:
- This investigation is for legitimate corporate security purposes
- I have reviewed the legal risks (WhatsApp ToS violation, account ban)
- I understand this tool uses unofficial WhatsApp integration
- A dedicated investigation phone number will be used (not personal)
- Results will be handled per company data privacy policies

Investigator Signature: _________________ Date: _________

Legal Approval: ________________________ Date: _________
```

Save as: `investigation_authorization.txt`

---

**END OF SETUP GUIDE**

Last Updated: 2026-01-02
Version: 1.0
