# Telegram Account Verification - Complete Setup Guide

**⚠️ CRITICAL WARNING: UNOFFICIAL TELEGRAM VERIFICATION TOOL**

This tool uses the **Telegram MTProto API** (unofficial client implementation) to automate account existence checks. This **VIOLATES** Telegram Terms of Service for automated lookups and carries risk of your account or phone number being **PERMANENTLY BANNED**.

---

## Table of Contents

1. [Legal & Compliance Prerequisites](#legal--compliance-prerequisites)
2. [Intended Use Case](#intended-use-case)
3. [Operational Security Overview](#operational-security-overview)
4. [Setup Requirements](#setup-requirements)
5. [Step-by-Step Setup](#step-by-step-setup)
6. [Obtaining Telegram API Credentials](#obtaining-telegram-api-credentials)
7. [First-Time Authentication](#first-time-authentication)
8. [Daily Usage Workflow](#daily-usage-workflow)
9. [Understanding the Results](#understanding-the-results)
10. [Troubleshooting](#troubleshooting)
11. [Best Practices & Rate Limiting](#best-practices--rate-limiting)
12. [Investigation Closure & Cleanup](#investigation-closure--cleanup)
13. [FAQ](#faq)

---

## Legal & Compliance Prerequisites

**STOP**: Before proceeding, you **MUST** have:

### ✅ Required Authorizations

1. **Written Authorization from Legal/Compliance Department**
   - Document the specific investigation case
   - Obtain approval signature from authorized personnel
   - File authorization form with compliance team

2. **Documented Security Use Case**
   - BEC (Business Email Compromise) investigation
   - CEO impersonation / phishing attack
   - Smishing (SMS phishing) investigation
   - Threat actor attribution
   - Fraud prevention / incident response

3. **Investigation Authorization Form** (Template below)

### 📋 Authorization Form Template

```
TELEGRAM ACCOUNT VERIFICATION - INVESTIGATION AUTHORIZATION

Case ID: _______________________
Investigation Type: [ ] BEC  [ ] Phishing  [ ] Smishing  [ ] Other: __________
Investigator Name: _______________________
Department: Security Operations / Incident Response
Date: _______________________

PHONE NUMBER(S) TO BE CHECKED:
1. _______________________
2. _______________________
3. _______________________

JUSTIFICATION:
[Describe the threat, impact, and why Telegram verification is necessary]

LEGAL REVIEW:
☐ Legal department has reviewed this request
☐ Investigation complies with applicable laws (CFAA, ECPA, etc.)
☐ Dedicated investigation phone number will be used (NOT personal account)
☐ All checks will be logged for compliance audit

Legal Approver: _______________________ Date: _______
Signature: _______________________

COMPLIANCE REVIEW:
☐ Complies with company investigation policy
☐ Data retention requirements documented
☐ Privacy impact assessment completed (if required)

Compliance Approver: _______________________ Date: _______
Signature: _______________________
```

**File this form** before conducting any checks. Retain for minimum 7 years per compliance requirements.

---

## Intended Use Case

### ✅ Legitimate Uses (Authorized Only)

- **Corporate Security Investigations**: BEC fraud, executive impersonation
- **Incident Response**: Active phishing/smishing campaigns targeting your organization
- **Threat Actor Attribution**: Identifying repeat attackers across incidents
- **Fraud Prevention**: Verifying suspicious contact methods before financial transactions
- **Industry Threat Sharing**: Sharing IOCs with security partners

### ❌ Prohibited Uses

- Personal investigations or stalking
- Harassment or intimidation
- Unauthorized surveillance
- Spam or bulk messaging
- Marketing or sales prospecting
- Any use without proper authorization
- Personal curiosity or non-work investigations

**Misuse of this tool can result in**:
- Termination of employment
- Legal liability (CFAA violations, etc.)
- Civil lawsuits
- Criminal charges

---

## Operational Security Overview

### Investigation Phone Number Strategy

**CRITICAL**: Do **NOT** use personal Telegram accounts or company executive numbers.

**Recommended Approach**:
1. Obtain dedicated Google Voice number (free)
2. Register Telegram on investigation workstation with that number
3. Use this number **ONLY** for security investigations
4. Rotate number every 90 days or if compromised

### OpSec Principles

✅ **DO**:
- Use dedicated investigation phone number (Google Voice)
- Isolate on dedicated investigation workstation
- Document all checks (automatic logging)
- Rotate investigation numbers every 90 days
- Wait 5-10 seconds between checks (rate limiting)
- Encrypt log files
- Use VPN if checking from corporate network

❌ **DO NOT**:
- Use personal Telegram accounts
- Use company executive phone numbers
- Check more than 20-30 numbers per day
- Use for unauthorized investigations
- Share session files (.telegram_session)
- Commit session files to git repositories
- Use on personal devices

---

## Setup Requirements

### Hardware/Software

- **Operating System**: macOS, Linux, or Windows
- **Node.js**: Version 18.0.0 or higher
- **Investigation Workstation**: Dedicated machine (not personal laptop)
- **Internet Connection**: Required for Telegram API access

### Investigation Phone Number

**Option 1: Google Voice (Recommended - Free)**
- US-based phone number
- Free SMS/voice capabilities
- Can receive Telegram verification codes
- Easy to decommission after investigation

**Option 2: Burner Phone / SIM Card**
- Physical burner phone with prepaid SIM
- Costs ~$20-50 for phone + SIM
- More secure but less convenient

**Option 3: Virtual Number Service**
- Twilio, Telnyx, or similar (paid)
- More expensive (~$1-5/month)
- Professional option for ongoing investigations

### Telegram API Credentials

Unlike WhatsApp (which uses QR code), Telegram requires API credentials:
- **api_id**: Numeric application identifier
- **api_hash**: Application authentication hash

**You must obtain these from Telegram** (see next section).

---

## Step-by-Step Setup

### Phase 1: Get Investigation Phone Number (Google Voice)

1. **Create Google Account** (if needed):
   - Go to https://accounts.google.com/signup
   - Use investigation-specific email (e.g., `security-investigations@yourcompany.com`)
   - **Do NOT use personal Google account**

2. **Get Google Voice Number**:
   - Go to https://voice.google.com
   - Sign in with investigation Google account
   - Click "Get Google Voice"
   - Select a phone number (choose area code strategically)
   - Link to verification number (can use personal cell temporarily for setup only)
   - Complete verification

3. **Configure Google Voice**:
   - Enable SMS forwarding to email (for code retrieval)
   - Disable voicemail transcription (privacy)
   - Set greeting to generic message
   - **Document the number** in investigation file

### Phase 2: Install Telegram on Investigation Device

**Important**: Install on the **investigation workstation** where you'll run the script, NOT on a mobile device.

1. **Download Telegram Desktop**:
   - Go to https://desktop.telegram.org/
   - Download for your OS (macOS/Windows/Linux)
   - Install to investigation workstation

2. **Register Telegram Account**:
   - Open Telegram Desktop
   - Click "Start Messaging"
   - Enter your Google Voice number (e.g., `+1-555-123-4567`)
   - Wait for verification code (SMS to Google Voice)
   - Check Google Voice for code or email forwarding
   - Enter verification code in Telegram
   - Set display name (e.g., "Security Investigation")
   - **Optional**: Set username (e.g., `@wmg_security_temp`)

3. **Configure Privacy Settings**:
   - Go to Settings → Privacy and Security
   - **Phone Number**: "Nobody" can see your phone number
   - **Last Seen**: "Nobody"
   - **Profile Photo**: "My Contacts" or "Nobody"
   - **Calls**: "My Contacts" or "Nobody"
   - **Groups**: "My Contacts"
   - **Disable**: "Suggest frequent contacts"
   - **Clear**: "Delete Synced Contacts" (important!)

4. **Optional Security**:
   - Enable Two-Factor Authentication (Settings → Privacy → Two-Step Verification)
   - Set a password (document securely in password manager)
   - **Remember this password** - you'll need it for script authentication

### Phase 3: Install Node.js

1. **Check if Node.js is installed**:
   ```bash
   node --version
   ```
   If version 18.0.0 or higher appears, skip to Phase 4.

2. **Install Node.js** (if needed):
   - **macOS** (using Homebrew):
     ```bash
     brew install node
     ```
   - **macOS/Linux** (using nvm - recommended):
     ```bash
     curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
     source ~/.bashrc  # or ~/.zshrc
     nvm install 18
     nvm use 18
     ```
   - **Windows**:
     - Download from https://nodejs.org/
     - Run installer (LTS version recommended)

3. **Verify Installation**:
   ```bash
   node --version  # Should show v18.0.0 or higher
   npm --version   # Should show 8.0.0 or higher
   ```

### Phase 4: Install Script Dependencies

1. **Navigate to scripts directory**:
   ```bash
   cd /path/to/phone-osint/scripts
   ```

2. **Install npm packages**:
   ```bash
   npm install
   ```

   This installs:
   - `telegram` (v2.18.0) - Telegram MTProto API client
   - `input` (v1.0.1) - Interactive CLI input
   - Plus WhatsApp dependencies if not already installed

3. **Verify Installation**:
   ```bash
   ls node_modules/telegram  # Should exist
   ```

---

## Obtaining Telegram API Credentials

**CRITICAL STEP**: You must obtain `api_id` and `api_hash` from Telegram before first use.

### Step-by-Step Process

1. **Go to Telegram API Development Tools**:
   - Open browser to https://my.telegram.org/auth
   - **Use your investigation Telegram account** (the Google Voice number you just set up)

2. **Login with Phone Number**:
   - Enter your Google Voice number (e.g., `+15551234567`)
   - Click "Next"
   - Telegram will send verification code to your Telegram account
   - Open Telegram Desktop → Check for code message
   - Enter code on website

3. **Navigate to API Development Tools**:
   - After login, click "API development tools"
   - Fill out the form:
     - **App title**: `WMG Security Investigation Tool` (or your company name)
     - **Short name**: `wmg_security` (alphanumeric, no spaces)
     - **Platform**: Select "Desktop"
     - **Description**: `Corporate security investigation tool for BEC/phishing response`
   - Click "Create application"

4. **Save Your Credentials**:
   - You'll see:
     ```
     App api_id: 12345678
     App api_hash: 1234567890abcdef1234567890abcdef
     ```
   - **SAVE THESE SECURELY** in password manager
   - **DO NOT share** or commit to git
   - You'll enter these when running the script for the first time

5. **Security Notes**:
   - These credentials are tied to your investigation Telegram account
   - Keep them confidential (treat like passwords)
   - If compromised, revoke at https://my.telegram.org/apps and create new app

---

## First-Time Authentication

When you run the script for the first time, it will prompt for setup.

### First Run Walkthrough

1. **Run the script** with a test number:
   ```bash
   node telegram_check.js "+1-555-000-0000"
   ```

2. **Legal Warning Display**:
   ```
   ================================================================================
   WARNING: UNOFFICIAL TELEGRAM VERIFICATION TOOL
   ================================================================================

   ⚠️  TERMS OF SERVICE CONSIDERATIONS
   This tool uses Telegram MTProto API for automated lookups.
   Excessive automated use may result in account restrictions.

   [... full legal warning ...]
   ```
   Read carefully.

3. **First-Time Setup Prompt**:
   ```
   ⚠️  FIRST-TIME SETUP REQUIRED

   You need Telegram API credentials (api_id and api_hash).
   See TELEGRAM_SETUP.md for instructions on obtaining these.

   Enter your Telegram API ID:
   ```
   → Enter the `api_id` you obtained (e.g., `12345678`)

   ```
   Enter your Telegram API Hash:
   ```
   → Enter the `api_hash` you obtained (e.g., `1234567890abcdef1234567890abcdef`)

   ```
   ✓ Configuration saved
   ```

4. **Authorization Confirmation**:
   ```
   Do you have written authorization for this investigation? (yes/no)
   Authorization confirmed:
   ```
   → Type `yes` (only if you have proper authorization!)

5. **Phone Number Authentication**:
   ```
   🔄 Initializing Telegram client...

   Enter your investigation phone number (Telegram account):
   ```
   → Enter your Google Voice number (e.g., `+15551234567`)

6. **Verification Code**:
   ```
   📱 Telegram will send you a verification code
   Enter the code you received:
   ```
   → Check Telegram Desktop for code message (arrives in "Telegram" official account)
   → Enter the 5-digit code

7. **Two-Factor Password** (if enabled):
   ```
   Enter your 2FA password (if enabled):
   ```
   → Enter your 2FA password (if you set one) or press Enter to skip

8. **Authenticated**:
   ```
   ✓ Telegram client authenticated
   ```
   Session is saved to `.telegram_session` file for future use.

9. **Check Execution**:
   The script proceeds to check the phone number you provided and displays results.

### Session Persistence

After first authentication:
- **Session saved**: `.telegram_session` file stores your login session
- **Config saved**: `.telegram_config.json` stores api_id and api_hash
- **Future runs**: Won't ask for credentials or phone code again (session persists)
- **Session expiry**: Sessions can expire after ~3-6 months of inactivity

---

## Daily Usage Workflow

Once set up, daily use is simple.

### Checking a Single Number

```bash
cd /path/to/phone-osint/scripts

# Check if +1-937-536-1299 is on Telegram
node telegram_check.js "+1-937-536-1299"
```

**Expected Output**:
```
================================================================================
WARNING: UNOFFICIAL TELEGRAM VERIFICATION TOOL
================================================================================
[... legal warning ...]

Do you have written authorization for this investigation? (yes/no)
Authorization confirmed: yes

🔄 Initializing Telegram client...
✓ Telegram client authenticated

================================================================================
TELEGRAM VERIFICATION RESULT
================================================================================

Phone Number:     +1-937-536-1299
Formatted:        19375361299
Telegram Account: ✓ REGISTERED
User ID:          123456789
Username:         @johndoe
First Name:       John
Last Name:        Doe
Verified:         No
Premium:          No
Bot:              No
Timestamp:        2026-01-02T19:30:45.123Z

================================================================================

Result saved to: ../logs/telegram_result_1735848645123.json
```

### Checking Multiple Numbers

**Option 1: Sequential checks with delay** (recommended)

Create a batch script `check_telegram_batch.sh`:

```bash
#!/bin/bash
# Telegram batch checker with rate limiting

NUMBERS=(
    "+1-555-0001"
    "+1-555-0002"
    "+1-555-0003"
)

for num in "${NUMBERS[@]}"; do
    echo "Checking $num..."
    node telegram_check.js "$num"

    # Wait 10 seconds between checks (rate limiting)
    echo "Waiting 10 seconds..."
    sleep 10
done

echo "Batch check complete!"
```

Run:
```bash
chmod +x check_telegram_batch.sh
./check_telegram_batch.sh
```

**Option 2: Manual checks with pauses**

```bash
node telegram_check.js "+1-555-0001"
# Wait ~10 seconds manually
node telegram_check.js "+1-555-0002"
# Wait ~10 seconds manually
node telegram_check.js "+1-555-0003"
```

---

## Understanding the Results

### Result Fields Explained

| Field | Description | Example |
|-------|-------------|---------|
| **Phone Number** | Original input | `+1-937-536-1299` |
| **Formatted** | Cleaned number (digits only) | `19375361299` |
| **Telegram Account** | Registration status | `✓ REGISTERED` or `✗ NOT FOUND` |
| **User ID** | Telegram user identifier | `123456789` |
| **Username** | Telegram @username (if set) | `@johndoe` or `Not set` |
| **First Name** | Display first name | `John` |
| **Last Name** | Display last name (if set) | `Doe` or `Not set` |
| **Verified** | Official verification badge | `Yes (✓)` or `No` |
| **Premium** | Telegram Premium subscriber | `Yes` or `No` |
| **Bot** | Bot account indicator | `Yes (Bot Account)` or `No` |
| **Timestamp** | Check timestamp (ISO 8601) | `2026-01-02T19:30:45.123Z` |

### Exit Codes

The script returns different exit codes for automation:

- **0**: Telegram account **FOUND** (registered)
- **1**: Error occurred during check
- **2**: Telegram account **NOT FOUND** (not registered)

**Using in shell scripts**:
```bash
if node telegram_check.js "+1-555-1234"; then
    echo "✓ Number has Telegram account"
else
    echo "✗ Number not on Telegram or error occurred"
fi
```

### Log Files

**Daily Investigation Log**:
```
logs/telegram_investigations_2026-01-02.json
```
Contains all checks performed that day (one JSON object per line).

**Individual Result Files**:
```
logs/telegram_result_1735848645123.json
```
Full JSON result for each check (timestamp in filename).

**Sample JSON Result**:
```json
{
  "phoneNumber": "+1-937-536-1299",
  "formattedNumber": "19375361299",
  "isRegistered": true,
  "userId": "123456789",
  "username": "johndoe",
  "firstName": "John",
  "lastName": "Doe",
  "isBot": false,
  "isPremium": false,
  "isVerified": false,
  "timestamp": "2026-01-02T19:30:45.123Z"
}
```

---

## Troubleshooting

### Common Issues & Solutions

#### Issue: "First-Time Setup Required" Every Time

**Cause**: Configuration file not being saved or not found.

**Solution**:
```bash
# Check if config file exists
ls -la .telegram_config.json

# Check permissions (should be readable/writable)
chmod 600 .telegram_config.json

# If missing, delete session and re-authenticate
rm .telegram_session
node telegram_check.js "+1-555-0000"
```

#### Issue: "Authentication Failed" or "Session Expired"

**Cause**: Session file expired or corrupted.

**Solution**:
```bash
# Delete session file
rm .telegram_session

# Re-run script (will prompt for phone code again)
node telegram_check.js "+1-555-0000"
```

#### Issue: "Invalid Phone Number" Error

**Cause**: Phone number format not recognized.

**Solution**:
- Use international format: `+1-555-123-4567`
- Remove spaces and special characters: `+15551234567`
- Ensure country code is included (e.g., `+1` for US)

#### Issue: "Telegram Account NOT FOUND" (False Negative)

**Possible Causes**:
1. Number genuinely not registered on Telegram
2. User has extreme privacy settings (unlikely to affect this check)
3. Number format issue (try reformatting)

**Troubleshooting**:
```bash
# Try different formats
node telegram_check.js "+1-555-123-4567"
node telegram_check.js "15551234567"
node telegram_check.js "+15551234567"

# Manual verification: Add contact in Telegram Desktop and check if profile appears
```

#### Issue: "FLOOD_WAIT" Error

**Cause**: Telegram rate limiting (too many checks too quickly).

**Error Message**:
```
Error: FLOOD_WAIT_X (wait X seconds before retrying)
```

**Solution**:
- Wait the specified number of seconds (could be 10 seconds to several hours)
- Reduce check frequency (longer delays between checks)
- Limit to 20-30 checks per day
- If severe, may need to wait 24 hours

#### Issue: "Account Banned" or "Phone Number Banned"

**Cause**: Telegram detected automated behavior and banned your investigation number.

**What to Do**:
1. **Accept the loss** of that investigation number
2. **DO NOT appeal** to Telegram (would reveal unauthorized tool use)
3. **Document in incident log**:
   ```
   Investigation number +1-555-123-4567 banned by Telegram on 2026-01-02
   Reason: Suspected automated use / rate limit violation
   Action: Decommissioned number, obtained new Google Voice number
   ```
4. **Get new Google Voice number** and start fresh
5. **Review rate limiting** practices (were you checking too frequently?)

#### Issue: Missing `api_id` or `api_hash`

**Cause**: Configuration file deleted or credentials not entered correctly.

**Solution**:
1. Check if config exists: `cat .telegram_config.json`
2. If missing or corrupted, delete and re-run:
   ```bash
   rm .telegram_config.json
   node telegram_check.js "+1-555-0000"
   ```
3. Re-enter API credentials from password manager

#### Issue: "Cannot Find Module 'telegram'"

**Cause**: npm dependencies not installed.

**Solution**:
```bash
cd /path/to/phone-osint/scripts
npm install
```

---

## Best Practices & Rate Limiting

### Avoiding Account Bans

**Critical Rate Limiting Rules**:

1. **⏱️ Wait 5-10 seconds between checks**
   - Minimum 5 seconds for low-volume investigations
   - 10-15 seconds for higher-volume
   - **Never** check continuously without delays

2. **📊 Limit checks to 20-30 per day maximum**
   - Spread checks throughout the day
   - Don't check 30 numbers in 10 minutes
   - Consider 10-15 checks per day for safety

3. **🔄 Rotate investigation numbers every 90 days**
   - Even if not banned, proactively get new number
   - Reduces long-term pattern detection
   - Document rotation in investigation files

4. **🚫 Use investigation number ONLY for checks**
   - Don't send messages from investigation account
   - Don't join groups or channels
   - Don't browse Telegram with investigation account
   - Minimize "human" activity to reduce ban risk

### Investigation Workflow Best Practices

✅ **DO**:
- Document each check in case file
- Link to log file (e.g., `logs/telegram_result_[timestamp].json`)
- Cross-reference with other OSINT sources
- Verify findings with manual Telegram app check (if critical)
- Encrypt log files when archiving
- Follow up on high-value finds (e.g., verified accounts impersonating executives)

❌ **DO NOT**:
- Check personal contacts or non-investigation numbers
- Share session files with other investigators (separate accounts)
- Run checks from personal devices
- Check numbers without authorization
- Use for curiosity or non-work purposes

### Security Hygiene

**Workstation Security**:
- Dedicated investigation workstation (not personal laptop)
- Full-disk encryption enabled
- Strong password / biometric login
- Automatic screen lock after 5 minutes idle
- VPN connection if on corporate network

**Data Security**:
- Encrypt log files: `zip -e investigation_logs.zip logs/`
- Store encrypted archives on secure file server
- Delete local logs after archiving (per retention policy)
- Limit access to investigation files (need-to-know basis)

**Session Security**:
- Never commit `.telegram_session` or `.telegram_config.json` to git
- Store session files on encrypted volume only
- Delete session files when investigation closes
- Don't copy session files to other machines

---

## Investigation Closure & Cleanup

When investigation is complete, follow proper decommissioning:

### Closure Checklist

- [ ] **Results documented in case file**
  - Attach JSON logs
  - Summarize key findings (which numbers had Telegram, usernames, etc.)
  - Note any verified accounts or impersonation indicators

- [ ] **Logs archived**:
  ```bash
  # Create encrypted archive
  cd /path/to/phone-osint
  zip -e -r case-BEC-2026-001-telegram.zip logs/
  # Enter strong password when prompted

  # Move to secure archive location
  mv case-BEC-2026-001-telegram.zip ~/archives/investigations/
  ```

- [ ] **Telegram session cleared**:
  ```bash
  cd /path/to/phone-osint/scripts
  rm .telegram_session
  rm .telegram_config.json
  ```

- [ ] **Authorization form filed**:
  - File signed authorization form with compliance department
  - Attach case summary and findings
  - Retain per compliance policy (minimum 7 years)

- [ ] **Investigation number decommissioned** (if rotating):
  ```bash
  # Delete Google Voice number
  # 1. Go to https://voice.google.com/settings
  # 2. Click "Delete" next to investigation number
  # 3. Confirm deletion

  # If keeping number for future investigations:
  # - Unlink from Telegram (see below)
  # - Document in investigation number registry
  ```

- [ ] **Telegram account unlinked** (if decommissioning):
  - Open Telegram Desktop
  - Settings → Devices → Terminate All Other Sessions
  - (Optional) Delete Telegram account: Settings → Privacy → Delete My Account

### Permanent Decommissioning

**If investigation number is compromised or banned**:

1. **Immediately unlink**:
   - Telegram Desktop → Settings → Privacy → Security → Active Sessions → Terminate All

2. **Delete Google Voice number**:
   - https://voice.google.com/settings → Delete number

3. **Notify security team lead**:
   ```
   Subject: Investigation Number Compromised - BEC-2026-001

   Investigation number +1-555-123-4567 has been compromised/banned.
   Date: 2026-01-02
   Reason: [Telegram ban / suspected detection / etc.]
   Action Taken: Number deleted, session cleared, logs archived
   New Number: Obtaining new Google Voice number for future investigations
   ```

4. **Document in incident log**:
   - Case ID, date, reason for compromise
   - Actions taken
   - Lessons learned (e.g., "checked too frequently, need longer delays")

---

## FAQ

### Q: How often can I safely check numbers?

**A**: Conservative recommendation:
- **5-10 seconds** between individual checks
- **20-30 checks maximum** per day
- **Spread checks** throughout the day (don't batch 30 in 10 minutes)
- **Rotate numbers** every 90 days even if not banned

### Q: What if the script says "NOT FOUND" but I know the number has Telegram?

**A**: Try:
1. Different phone number formats (`+1-555-123-4567` vs `15551234567`)
2. Manual verification: Add contact in Telegram Desktop and see if profile appears
3. Check if user has extreme privacy settings (unlikely but possible)
4. Verify number hasn't been ported or changed

### Q: Can Telegram detect that I'm using this tool?

**A**: **Yes**, Telegram can potentially detect:
- Automated API usage patterns
- High-frequency checks
- Unusual contact import/delete behavior
- Lack of "normal" human activity on the account

**Risk mitigation**:
- Use rate limiting (delays between checks)
- Don't check excessively (20-30/day max)
- Dedicated investigation number (accept potential loss)

### Q: What happens if my investigation number gets banned?

**A**:
- Accept the loss (don't appeal to Telegram)
- Document in incident log
- Get new Google Voice number
- Start fresh with new Telegram account
- Review rate limiting practices

### Q: How long do sessions last?

**A**: Telegram sessions can last:
- **Active use**: Indefinitely (as long as you check regularly)
- **Inactive**: ~3-6 months before expiring
- **Security**: Telegram may invalidate sessions if suspicious activity detected

If session expires, delete `.telegram_session` and re-authenticate.

### Q: Can I run this on multiple machines?

**A**: **Not recommended**. Session files are machine-specific and sharing them:
- May trigger security alerts
- Could lead to session invalidation
- Violates best practices

**Better approach**: Set up separate investigation accounts per machine if needed.

### Q: Is this legal?

**A**: **Legal gray area**:
- Violates Telegram ToS (not necessarily illegal, but against their rules)
- Could violate CFAA if used without authorization
- Legal if done for legitimate corporate security with proper authorization
- **Always obtain legal/compliance approval before use**

**Not legal advice** - consult your legal department.

### Q: What information can I get from Telegram checks?

**A**: The tool retrieves:
- ✅ Whether number is registered on Telegram
- ✅ User ID (unique identifier)
- ✅ Username (if user has set one, e.g., @johndoe)
- ✅ First and last name (display name)
- ✅ Verification status (blue checkmark)
- ✅ Premium status (Telegram Premium subscriber)
- ✅ Bot indicator (if account is a bot)

**Cannot retrieve**:
- ❌ Private messages
- ❌ Contact lists
- ❌ Group memberships (unless public)
- ❌ Last seen / online status (usually hidden)

### Q: How do I update the tool?

**A**:
```bash
cd /path/to/phone-osint/scripts
npm update
```

Check for new versions of the telegram library periodically.

---

## Emergency Contacts

### If Investigation Number Compromised

1. **Immediately unlink** from Telegram (Settings → Terminate All Sessions)
2. **Delete** Google Voice number
3. **Notify** security team lead
4. **Document** in incident log
5. **Obtain** new investigation number

### If Account Banned

1. **Accept loss** of investigation number
2. **DO NOT appeal** to Telegram (reveals tool use)
3. **Document** in incident log with lessons learned
4. **Get new number** and start fresh
5. **Review rate limiting** practices to avoid repeat ban

### If Legal/Compliance Questions

**Contact**:
- **WMG Legal Department** BEFORE use if unsure
- **Compliance Team** for authorization questions
- **Security Team Lead** for operational guidance

### Technical Support

**Tool Issues**:
- **Author**: Paul Kincaid <paul@pksecure.io>
- **Documentation**: This file + TELEGRAM_QUICKSTART.md
- **Logs**: Check `logs/telegram_investigations_[date].json` for errors

---

## Appendix: Technical Details

### How It Works

1. **MTProto API**: The script uses Telegram's MTProto protocol (same as official clients)
2. **ImportContacts Method**: Imports phone number as temporary contact
3. **Check Registration**: If contact import succeeds, number is registered
4. **Retrieve Details**: Fetches user profile info (username, name, etc.)
5. **Cleanup**: Deletes imported contact to minimize trace
6. **Logging**: Records check in JSON log files

### Session Management

- **StringSession**: Session stored as encrypted string in `.telegram_session`
- **Persistence**: Session persists across script runs (no re-authentication needed)
- **Security**: Session file should have restrictive permissions (600)

### Privacy Considerations

**What the check reveals to the target**:
- ❓ **Unknown** - Telegram doesn't notify users when contacts import them
- ❓ Contact import/delete happens in milliseconds (minimal trace)
- ⚠️ If you message them, they'll see your investigation number

**What Telegram knows**:
- ✅ Your investigation phone number
- ✅ IP address (use VPN if concerned)
- ✅ API credentials (app ID)
- ✅ Check frequency and patterns

---

**Last Updated**: 2026-01-02
**Version**: 1.0
**Author**: Paul Kincaid <paul@pksecure.io>
**License**: Apache-2.0

**For daily quick reference, see**: [TELEGRAM_QUICKSTART.md](TELEGRAM_QUICKSTART.md)
