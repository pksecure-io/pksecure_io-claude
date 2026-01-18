# WhatsApp Check - Quick Start Guide

**⚠️ UNAUTHORIZED USE VIOLATES WHATSAPP ToS - OBTAIN LEGAL APPROVAL FIRST**

This is a condensed quick-start for investigators already authorized and set up.

For full setup instructions, see: [WHATSAPP_SETUP.md](WHATSAPP_SETUP.md)

---

## Prerequisites (One-Time Setup)

1. ✅ Legal/compliance authorization obtained
2. ✅ Google Voice number set up (dedicated investigation number)
3. ✅ WhatsApp registered on investigation phone with Google Voice number
4. ✅ Node.js installed (v18+)
5. ✅ npm dependencies installed: `npm install` (in scripts/ directory)

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
node whatsapp_check.js "+1-937-536-1299"
```

### Step 3: First Time Only - QR Code Pairing

**If you see QR code** (first time or session expired):

1. Open WhatsApp on investigation phone
2. Tap Menu (⋮) → Linked Devices → Link a Device
3. Scan QR code on screen
4. Wait for "✓ WhatsApp client ready"

**Session saves automatically** - won't need QR code again until session expires.

### Step 4: Review Results

**Terminal Output**:
```
================================================================================
WHATSAPP VERIFICATION RESULT
================================================================================

Phone Number:     +1-937-536-1299
Formatted:        19375361299
WhatsApp Account: ✓ REGISTERED
Display Name:     [Name or "Unknown"]
Business Account: No
Timestamp:        2026-01-02T18:45:23.456Z

================================================================================

Result saved to: ../logs/whatsapp_result_1704218723456.json
```

### Step 5: Document in Case File

- Copy result to case notes
- Link log file: `logs/whatsapp_result_[timestamp].json`
- Update investigation timeline

---

## Common Commands

### Check Single Number
```bash
node whatsapp_check.js "+1-555-123-4567"
```

### Check Multiple Numbers (with delays)
```bash
# Create script: check_batch.sh
for num in "+1-555-0001" "+1-555-0002" "+1-555-0003"; do
    node whatsapp_check.js "$num"
    sleep 10  # Wait 10 seconds between checks
done
```

### Clear Session (if disconnected)
```bash
rm -rf .wwebjs_auth/
# Re-run script to get new QR code
```

### View Recent Logs
```bash
cd ../logs
tail -f whatsapp_investigations_$(date +%Y-%m-%d).json
```

---

## Number Formats Accepted

All formats work (script auto-converts):

```bash
node whatsapp_check.js "+1-555-123-4567"    # International (preferred)
node whatsapp_check.js "15551234567"        # No formatting
node whatsapp_check.js "(555) 123-4567"     # US format
node whatsapp_check.js "+44 20 7183 8750"   # UK/International
```

---

## Exit Codes

```
0 = WhatsApp account FOUND
2 = WhatsApp account NOT FOUND
1 = ERROR occurred
```

Use in scripts:
```bash
if node whatsapp_check.js "+1-555-1234"; then
    echo "✓ Has WhatsApp"
else
    echo "✗ No WhatsApp or error"
fi
```

---

## Troubleshooting Quick Fixes

| Problem | Quick Fix |
|---------|-----------|
| QR Code expired | Re-run script (QR expires in 60 sec) |
| "Authentication failed" | WhatsApp → Linked Devices → Unlink old sessions |
| "Session disconnected" | `rm -rf .wwebjs_auth/` then re-pair |
| Account banned | Get new Google Voice number, start over |
| Wrong result | Double-check number format (international: +1...) |

---

## Rate Limiting Best Practices

**To avoid account bans:**

- ⏱️ Wait 5-10 seconds between checks
- 📊 Limit to 20-30 checks per day
- 🔄 Rotate investigation numbers every 90 days
- 🚫 Don't use investigation WhatsApp for anything else

---

## Security Reminders

- 🔒 Use VPN if checking from corporate network
- 📝 Log all checks (automatic)
- 🔐 Encrypt log archive
- 🗑️ Unlink WhatsApp Web after investigation
- 🔄 Clear session: `rm -rf .wwebjs_auth/`

---

## Investigation Closure Checklist

After investigation complete:

- [ ] Results documented in case file
- [ ] Logs archived: `mv logs/ ~/archives/case-[ID]/`
- [ ] WhatsApp Web unlinked: Phone → Linked Devices → Log Out
- [ ] Session cleared: `rm -rf .wwebjs_auth/`
- [ ] Authorization form filed

---

## Emergency Contacts

**If investigation number is compromised:**
1. Immediately unlink from WhatsApp Web
2. Delete Google Voice number
3. Get new investigation number
4. Notify security team lead

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

# 2. Check if WhatsApp account exists
node whatsapp_check.js "+1-555-987-6543"

# 3. Result: ✓ REGISTERED
#    - Display Name: "CEO John Smith" (impersonation!)
#    - Business: No (red flag - real CEO would use business account)

# 4. Document findings
echo "WhatsApp: REGISTERED (impersonation suspected)" >> investigation_log.txt

# 5. Cross-check with other threat intel
# 6. Share with security team / law enforcement
```

---

**For full documentation, see**: [WHATSAPP_SETUP.md](WHATSAPP_SETUP.md)

**Legal questions**: Contact WMG Legal BEFORE use

**Technical issues**: paul@pksecure.io

Last Updated: 2026-01-02
