# Telegram Check - Quick Start Guide

**⚠️ UNAUTHORIZED USE VIOLATES TELEGRAM ToS - OBTAIN LEGAL APPROVAL FIRST**

This is a condensed quick-start for investigators already authorized and set up.

For full setup instructions, see: [TELEGRAM_SETUP.md](TELEGRAM_SETUP.md)

---

## Prerequisites (One-Time Setup)

1. ✅ Legal/compliance authorization obtained
2. ✅ Google Voice number set up (dedicated investigation number)
3. ✅ Telegram registered on investigation workstation with Google Voice number
4. ✅ Telegram API credentials obtained (api_id and api_hash)
5. ✅ Node.js installed (v18+)
6. ✅ npm dependencies installed: `npm install` (in scripts/ directory)
7. ✅ First-time authentication completed (session saved)

---

## Daily Workflow

### Step 1: Get Authorization

```
Case ID: [Enter case number]
Threat: BEC / CEO Fraud / Phishing
Phone numbers: [List numbers to check]
Authorization: [Legal approval signature]
```

### Step 2: Run Check

```bash
cd /path/to/phone-osint/scripts

# Check single number
node telegram_check.js "+1-937-536-1299"
```

### Step 3: First Time Only - Authentication

**If you see authentication prompts** (first time or session expired):

1. **API Credentials** (one-time):
   ```
   Enter your Telegram API ID: [your api_id]
   Enter your Telegram API Hash: [your api_hash]
   ```

2. **Phone Number**:
   ```
   Enter your investigation phone number (Telegram account): +15551234567
   ```

3. **Verification Code**:
   ```
   📱 Telegram will send you a verification code
   Enter the code you received: [5-digit code]
   ```
   Check Telegram Desktop for code (arrives from "Telegram" official account)

4. **2FA Password** (if enabled):
   ```
   Enter your 2FA password (if enabled): [password or press Enter]
   ```

**Session saves automatically** - won't need authentication again until session expires.

### Step 4: Review Results

**Terminal Output**:
```
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

### Step 5: Document in Case File

- Copy result to case notes
- Link log file: `logs/telegram_result_[timestamp].json`
- Update investigation timeline

---

## Common Commands

### Check Single Number
```bash
node telegram_check.js "+1-555-123-4567"
```

### Check Multiple Numbers (with delays)
```bash
# Create script: check_telegram_batch.sh
for num in "+1-555-0001" "+1-555-0002" "+1-555-0003"; do
    node telegram_check.js "$num"
    sleep 10  # Wait 10 seconds between checks
done
```

### Clear Session (if disconnected)
```bash
rm .telegram_session
rm .telegram_config.json
# Re-run script to re-authenticate
```

### View Recent Logs
```bash
cd ../logs
tail -f telegram_investigations_$(date +%Y-%m-%d).json
```

---

## Number Formats Accepted

All formats work (script auto-converts):

```bash
node telegram_check.js "+1-555-123-4567"    # International (preferred)
node telegram_check.js "15551234567"        # No formatting
node telegram_check.js "(555) 123-4567"     # US format
node telegram_check.js "+44 20 7183 8750"   # UK/International
```

---

## Exit Codes

```
0 = Telegram account FOUND
2 = Telegram account NOT FOUND
1 = ERROR occurred
```

Use in scripts:
```bash
if node telegram_check.js "+1-555-1234"; then
    echo "✓ Has Telegram"
else
    echo "✗ No Telegram or error"
fi
```

---

## Troubleshooting Quick Fixes

| Problem | Quick Fix |
|---------|-----------|
| "First-time setup required" | Re-enter api_id and api_hash (check password manager) |
| "Authentication failed" | `rm .telegram_session` then re-run |
| "Session disconnected" | `rm .telegram_session` then re-run |
| "FLOOD_WAIT" error | Wait X seconds (Telegram rate limit), reduce check frequency |
| Account banned | Get new Google Voice number, start over |
| Wrong result | Double-check number format (international: +1...) |

---

## Rate Limiting Best Practices

**To avoid account bans:**

- ⏱️ Wait 5-10 seconds between checks
- 📊 Limit to 20-30 checks per day
- 🔄 Rotate investigation numbers every 90 days
- 🚫 Don't use investigation Telegram for anything else (no messaging, groups, etc.)

---

## Security Reminders

- 🔒 Use VPN if checking from corporate network
- 📝 Log all checks (automatic)
- 🔐 Encrypt log archive
- 🗑️ Clear session after investigation
- 🔄 Clear credentials: `rm .telegram_session .telegram_config.json`

---

## Investigation Closure Checklist

After investigation complete:

- [ ] Results documented in case file
- [ ] Logs archived: `zip -e case-[ID]-telegram.zip logs/`
- [ ] Session cleared: `rm .telegram_session .telegram_config.json`
- [ ] Authorization form filed
- [ ] (Optional) Investigation number decommissioned if rotating

---

## Emergency Contacts

**If investigation number is compromised:**
1. Immediately clear session: `rm .telegram_session`
2. Terminate all sessions: Telegram → Settings → Privacy → Active Sessions → Terminate All
3. Delete Google Voice number
4. Get new investigation number
5. Notify security team lead

**If account banned:**
1. Accept loss of investigation number
2. DO NOT appeal (reveals unofficial tool use)
3. Document in incident log
4. Get new number and start fresh

---

## Quick Example: BEC Investigation

**Scenario**: Received phishing email claiming to be CEO, includes phone number for "urgent wire transfer"

**Investigation Steps**:

```bash
# 1. Document authorization
echo "Case: BEC-2026-001" >> investigation_log.txt
echo "Number: +1-555-987-6543" >> investigation_log.txt

# 2. Check if Telegram account exists
node telegram_check.js "+1-555-987-6543"

# 3. Result: ✓ REGISTERED
#    - Username: @fake_ceo_john
#    - First Name: "CEO John Smith" (impersonation!)
#    - Verified: No (red flag - real CEO would be verified)
#    - Premium: Yes (threat actor invested in premium to look legit)

# 4. Document findings
echo "Telegram: REGISTERED (impersonation suspected, premium account)" >> investigation_log.txt

# 5. Cross-check with other threat intel
# 6. Share with security team / law enforcement
```

---

## Comparison: Telegram vs WhatsApp Checks

| Feature | Telegram | WhatsApp |
|---------|----------|----------|
| **Setup** | API credentials required | QR code pairing |
| **Authentication** | Phone code + optional 2FA | QR code scan |
| **Session** | StringSession file | .wwebjs_auth/ directory |
| **Data Retrieved** | Username, user ID, verified status | Display name, business status |
| **Rate Limiting** | ~20-30/day safe | ~20-30/day safe |
| **Ban Risk** | Moderate (Telegram monitors API use) | Moderate (WhatsApp monitors automation) |

**Recommendation**: Use both tools for comprehensive messaging platform coverage.

---

## API Credentials Reference

**Where to get**:
- Go to https://my.telegram.org/auth
- Login with investigation phone number
- Click "API development tools"
- Create app: Name = "WMG Security Investigation"
- Save `api_id` and `api_hash` to password manager

**What they look like**:
- `api_id`: Numeric (e.g., `12345678`)
- `api_hash`: 32-character hex (e.g., `1234567890abcdef1234567890abcdef`)

**Security**:
- Store in password manager
- Never commit to git
- If compromised, revoke and create new app

---

## Result JSON Structure

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

**Key Fields for Investigations**:
- `isRegistered`: Account exists
- `username`: Telegram @handle (can be searched publicly)
- `isVerified`: Blue checkmark (official accounts)
- `isPremium`: Paying subscriber (threat actors sometimes use premium)
- `isBot`: Automated bot account

---

## Integration with Phone OSINT Skill

Telegram checks complement the main phone-osint skill:

1. **Run phone OSINT first**:
   ```
   # In Claude Code
   Investigate phone number +1-555-987-6543
   ```

2. **If social media check needed, run Telegram**:
   ```bash
   cd phone-osint/scripts
   node telegram_check.js "+1-555-987-6543"
   ```

3. **Add findings to main OSINT report**:
   - Update "Social Media Presence" section
   - Note Telegram username if found
   - Cross-reference with spam reports

---

**For full documentation, see**: [TELEGRAM_SETUP.md](TELEGRAM_SETUP.md)

**Legal questions**: Contact WMG Legal BEFORE use

**Technical issues**: paul@pksecure.io

**Last Updated**: 2026-01-02
