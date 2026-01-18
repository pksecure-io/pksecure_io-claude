# Snapchat Check - Quick Start Guide

**🚨 EXTREME BAN RISK - MANUAL VERIFICATION ONLY RECOMMENDED**

This is a condensed quick-start for **MANUAL** Snapchat verification (recommended method).

For full setup and risk assessment, see: [SNAPCHAT_SETUP.md](SNAPCHAT_SETUP.md)

---

## ⚠️ Critical Warning

**Snapchat has the HIGHEST ban risk** of all messaging platforms. Automated checking will almost certainly result in permanent account ban within hours/days.

**STRONG RECOMMENDATION**: Use **manual verification only** (documented below).

---

## Prerequisites

1. ✅ Legal/compliance authorization obtained
2. ✅ Investigation phone with Snapchat app installed (iPhone or Android)
3. ✅ Snapchat account registered with Google Voice investigation number
4. ✅ Snapchat privacy settings configured (see setup guide)
5. ✅ Contacts sync enabled in Snapchat

---

## Manual Verification Workflow (RECOMMENDED)

### 5-Minute Per-Check Process

**This is the ONLY recommended method for Snapchat.**

#### Step 1: Add Contact to Phone (30 seconds)

```
Open Contacts app
→ Tap + (Add Contact)
→ Enter phone number: +1-555-987-6543
→ First Name: Investigation
→ Last Name: Target001
→ Save
```

#### Step 2: Sync in Snapchat (30 seconds)

```
Open Snapchat app
→ Tap Profile icon (top left)
→ Tap Add Friends (+)
→ Tap Contacts tab
→ Wait for sync (5-30 seconds)
→ Pull down to refresh if needed
```

#### Step 3: Check Result (1 minute)

**If Account Exists**:
- ✅ Contact appears in "Contacts" or "Quick Add" section
- Shows username (e.g., `@johndoe123`)
- Shows display name
- Shows Bitmoji avatar
- Tap profile to view details (DO NOT add them)

**If No Account**:
- ❌ Contact does NOT appear in Snapchat
- Only shows in phone's Contacts app

#### Step 4: Document Findings (2 minutes)

```
Take screenshots:
- Profile view with username
- Display name and Bitmoji

Record in case file:
Case: BEC-2026-001
Number: +1-555-987-6543
Result: ✓ REGISTERED or ✗ NOT FOUND
Username: @threat_actor_123
Display Name: John Smith
Snap Score: 12,543
Verified: No
```

#### Step 5: Clean Up (30 seconds)

```
Open Contacts app
→ Find "Investigation Target001"
→ Tap Edit
→ Delete Contact
→ Confirm

Do NOT:
❌ Add them as friend (leaves trace)
❌ Send Snap or message
❌ View private Stories
```

---

## Manual Verification - Complete Example

### Real Investigation Scenario

**Case**: BEC attack, suspect CEO impersonation
**Target Number**: +1-937-536-1299

```bash
# Step 1: Add to contacts (30 sec)
Contacts → + → "+1-937-536-1299" → "Investigation Target001" → Save

# Step 2: Sync in Snapchat (30 sec)
Snapchat → Profile → Add Friends → Contacts → Refresh

# Step 3: Check result (1 min)
✓ Account found in "Contacts" section
  Username: @fake_ceo_john
  Display Name: "CEO John Smith"
  Bitmoji: Professional business avatar
  Snap Score: 8,234
  Verified: No ⚠️ (red flag - real CEO would be verified)

# Step 4: Screenshots & document (2 min)
Screenshot saved: snapchat_profile_20260102_1430.png
Logged in case file: BEC-2026-001

# Step 5: Clean up (30 sec)
Contact deleted from phone

Total time: ~4 minutes
```

---

## Automated Method (NOT RECOMMENDED)

**⚠️ USE MANUAL METHOD INSTEAD**

Automated checking:
- ❌ 95%+ ban risk (almost certain)
- ❌ Libraries often broken/outdated
- ❌ Not worth the setup time
- ❌ Violates Snapchat ToS

**If you absolutely must try automated** (against all recommendations):

```bash
cd /path/to/phone-osint/scripts

# Will show manual verification guide (default)
python snapchat_check.py "+1-937-536-1299"

# Force automated attempt (NOT RECOMMENDED)
python snapchat_check.py "+1-937-536-1299" --force-automated

# Expected result: Library not available or account banned
```

---

## Comparison: Manual vs Automated

| Feature | Manual | Automated |
|---------|--------|-----------|
| **Ban Risk** | None | 95%+ |
| **Time per Check** | 4-5 minutes | 30 seconds (until banned) |
| **Setup Time** | 5 minutes | 2-4 hours |
| **Reliability** | 100% | 10-20% |
| **Sustainability** | Indefinite | Days/weeks until ban |
| **ToS Compliance** | ✅ Compliant | ❌ Violation |
| **Data Retrieved** | Username, name, Bitmoji, Stories | Username only (if works) |
| **Checks Before Ban** | Unlimited | 1-10 |

**Verdict**: Manual is faster, safer, and more reliable for Snapchat.

---

## Rate Limiting (Manual Method)

**Safe Limits**:
- ⏱️ 5-10 checks per day maximum
- 📊 Wait 30-60 minutes between checks
- 🔄 Spread throughout day (not all at once)
- 🗑️ Delete contact after each check

**Why**: Even manual contact syncing can trigger flags if excessive.

---

## Privacy Settings (One-Time Setup)

**Configure Snapchat Privacy**:

```
Snapchat → Profile → Settings (gear icon)

Who Can...
  Contact Me: My Friends
  View My Story: My Friends
  See My Location: Ghost Mode
  See Me in Quick Add: OFF ⚠️ (important!)

Additional Services
  Permissions → Contacts: Allow (required for sync)

Mobile Number
  Let Others Find Me: OFF (prevents targets from finding you)
```

---

## Platform Comparison

| Platform | Method | Time | Ban Risk | Data Quality |
|----------|--------|------|----------|--------------|
| **Snapchat** | Manual | 4-5 min | None | High (username, Bitmoji, Stories) |
| WhatsApp | Automated | 30 sec | Moderate | Medium (name, business) |
| Telegram | Automated | 30 sec | Moderate | High (username, verified) |

**Strategy**: Use automated for WhatsApp/Telegram, manual for Snapchat.

---

## Troubleshooting

| Problem | Quick Fix |
|---------|-----------|
| Contact not appearing | Check sync enabled: Settings → Permissions → Contacts |
| Wrong person found | Compare username with other OSINT sources |
| Account banned (manual) | Get new Google Voice number, reduce check frequency |
| Target might see me | Disable "Quick Add" in privacy settings |

---

## Investigation Closure Checklist

After investigation complete:

- [ ] Screenshots saved to case file
- [ ] All investigation contacts deleted from phone
- [ ] Results documented: `logs/snapchat_result_manual_[timestamp].json`
- [ ] Authorization form filed
- [ ] (Optional) Clear Snapchat cache: Settings → Clear Cache

---

## Emergency: If Investigation Account Banned

**Even with manual method**, account can be banned if:
- Too many contact syncs in short time
- VPN/suspicious IP usage
- Other ToS violations

**What to Do**:

```
1. Accept the ban (no appeal)
2. Get new Google Voice number
3. Register new Snapchat account
4. Wait 24-48 hours before resuming checks
5. Reduce check frequency
6. Document ban in incident log
```

---

## Manual Verification Template

**Copy this for each check**:

```
SNAPCHAT MANUAL VERIFICATION

Case: _______________
Date: _______________
Number: _______________

RESULT:
[ ] Snapchat account FOUND
[ ] Snapchat account NOT FOUND

DETAILS (if found):
Username: @_______________
Display Name: _______________
Bitmoji: Yes / No
Snap Score: _______________
Verified: Yes / No
Public Story: Yes / No

SCREENSHOTS:
- snapchat_profile_[timestamp].png

CONCLUSION:
_______________
```

---

## Quick Example: BEC Investigation

**Scenario**: Phishing email with phone number claiming to be CFO

```bash
# Investigation
Case ID: BEC-2026-002
Target: +1-555-123-9999
Claim: "CFO urgent wire transfer request"

# Manual Check (4 minutes)
1. Add contact to phone
2. Snapchat sync → Account FOUND
   Username: @fake_cfo_urgent
   Display Name: "CFO Sarah Johnson"
   Verified: No ⚠️
   Snap Score: 234 (very low - new account!)

# Analysis
- No verification badge (red flag)
- Very low Snap Score (account created recently)
- Username suspicious ("fake_cfo_urgent")
- Display name matches real CFO (impersonation)

# Conclusion
Strong evidence of CFO impersonation fraud
→ Escalate to security team / law enforcement
```

---

## Best Practices Summary

✅ **DO**:
- Use manual verification only
- Document with screenshots
- Delete contacts after check
- Wait 30-60 min between checks
- Configure privacy settings
- Cross-reference with WhatsApp/Telegram

❌ **DO NOT**:
- Add targets as friends
- Use automated tools (extreme ban risk)
- Sync too many contacts at once
- View private Stories
- Use personal Snapchat accounts

---

## Integration with Phone OSINT Skill

**Comprehensive messaging platform coverage**:

```bash
# 1. Run main phone OSINT (Claude Code)
Investigate phone number +1-555-987-6543

# 2. Check WhatsApp (automated - 30 seconds)
cd phone-osint/scripts
node whatsapp_check.js "+1-555-987-6543"

# 3. Check Telegram (automated - 30 seconds)
node telegram_check.js "+1-555-987-6543"

# 4. Check Snapchat (manual - 4 minutes)
# Follow manual verification steps above
# Add contact → Sync → Check → Document → Delete

# 5. Compile comprehensive report
# Combine all findings into investigation summary
```

**Total Time**: ~10-15 minutes for complete messaging platform coverage

---

## When to Use Snapchat Verification

**High-Value Use Cases**:
- ✅ Younger demographic targets (Snapchat popular with 18-34)
- ✅ Consumer-facing fraud (Snapchat common in social engineering)
- ✅ Impersonation cases (check if fraudster has Snapchat presence)

**Lower-Value Use Cases**:
- ⚠️ Enterprise targets (less common on Snapchat)
- ⚠️ International numbers (Snapchat less popular outside US)

**Skip Snapchat If**:
- Target unlikely to use Snapchat (older demographic, B2B context)
- Time-sensitive investigation (manual checking takes longer)
- WhatsApp/Telegram already provided sufficient evidence

---

## Data Retrieved Comparison

**Snapchat Manual** (most data):
- ✅ Username
- ✅ Display Name
- ✅ Bitmoji avatar (unique visual identifier)
- ✅ Snap Score (activity level indicator)
- ✅ Public Stories (if available)
- ✅ Verification badge (blue checkmark)
- ⚠️ Higher effort (manual)

**Telegram Automated**:
- ✅ Username
- ✅ First/Last Name
- ✅ User ID
- ✅ Verified status
- ✅ Premium status

**WhatsApp Automated**:
- ✅ Display Name
- ✅ Business account status
- ❌ No username (WhatsApp doesn't have usernames)

**Recommendation**: Use all three for maximum intelligence coverage.

---

## Log Format

**Manual verification log** (create JSON for audit):

```json
{
  "timestamp": "2026-01-02T14:30:00Z",
  "caseId": "BEC-2026-001",
  "phoneNumber": "+1-555-987-6543",
  "platform": "Snapchat",
  "method": "manual_verification",
  "isRegistered": true,
  "accountDetails": {
    "username": "threat_actor_123",
    "displayName": "John Smith",
    "hasBitmoji": true,
    "snapScore": 12543,
    "hasPublicStory": true,
    "isVerified": false
  },
  "investigator": "security@wmg.com",
  "screenshots": ["snapchat_profile_20260102_1430.png"],
  "notes": "Impersonation suspected - matches CEO name but not verified"
}
```

Save to: `logs/snapchat_result_manual_[timestamp].json`

---

**For full documentation, see**: [SNAPCHAT_SETUP.md](SNAPCHAT_SETUP.md)

**Legal questions**: Contact Legal Department BEFORE use

**Technical issues**: paul@pksecure.io

**Last Updated**: 2026-01-02

---

## Final Recommendation

**Use MANUAL verification for Snapchat.**

It's safer, more reliable, and actually faster than debugging broken automation. Save automation for WhatsApp and Telegram where it's more viable.

**Total Investigation Time per Phone Number**:
- WhatsApp: 30 seconds (automated)
- Telegram: 30 seconds (automated)
- Snapchat: 4 minutes (manual)
- **Total: ~5-6 minutes** for complete coverage

This is manageable for targeted investigations and far better than dealing with constant account bans from Snapchat automation.
