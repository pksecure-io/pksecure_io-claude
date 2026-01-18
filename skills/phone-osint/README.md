# Phone Number OSINT Lookup Skill

Comprehensive phone number Open Source Intelligence (OSINT) investigation skill for Claude Code. Analyzes phone numbers using publicly available sources to determine geographic location, carrier type, spam/scam reports, and potential social media presence.

**Version**: 0.2
**Stage**: Development
**Author**: Paul Kincaid <paul@pksecure.io>
**License**: Apache-2.0

## Overview

This skill performs systematic OSINT investigations on phone numbers by:

- **Parsing and validating** phone number formats (US, Canada, international)
- **Geographic location lookup** based on area codes and country codes
- **Carrier and line type detection** (mobile, landline, VoIP, virtual)
- **Spam/scam report checking** across multiple public databases
- **Social media presence detection** (limited by privacy protections)
- **Public records search** including business directories and registrations

All investigations use **free, publicly available sources** and emphasize ethical OSINT practices with proper privacy considerations.

## Supported Phone Number Formats

The skill handles multiple input formats:

| Format | Example | Notes |
|--------|---------|-------|
| US/Canada Parentheses | `(555) 123-4567` | Requires region hint or +1 prefix |
| US/Canada Hyphenated | `555-123-4567` | Requires region hint or +1 prefix |
| International E.164 | `+1-555-123-4567` | Preferred format, includes country code |
| International Space-Separated | `+44 20 7183 8750` | Common international format |
| Country Code Variants | `+33 1 23 45 67 89` | Any country code supported |

**Note**: Phone numbers without country codes are assumed to be US/Canada (+1) unless otherwise specified.

## Features

### Core OSINT Capabilities

✅ **Number Parsing & Validation**
- Robust format detection and normalization
- Country code and area code extraction
- Format validation (valid/possible number checks)

✅ **Geographic Location**
- NANP (North America) area code database lookup
- International country code identification
- City, state/province, and region mapping
- Time zone determination

✅ **Carrier & Line Type**
- Mobile vs. landline detection
- VoIP service identification
- Google Voice and virtual number detection
- Carrier name lookup (when available)

✅ **Spam/Scam Intelligence**
- Multi-source spam database searches
- Aggregated user report analysis
- Risk level assessment (Low/Medium/High)
- Scam type categorization

✅ **Social Media & Messaging Platform Checks**
- Public social media profile searches (LinkedIn, Facebook, Twitter, Instagram)
- Business contact information lookup
- Messaging platform searches: WhatsApp, Telegram, Snapchat
  - Web search for publicly posted associations
  - Manual verification guidance (ToS-compliant methods)
  - Privacy-respecting approach (no unauthorized lookups)
- Platform-specific link detection (wa.me, t.me, snapchat.com)
- Professional network searches (LinkedIn, etc.)
- Clear documentation of privacy limitations and manual verification requirements

✅ **Additional OSINT**
- Business directory listings (Yellow Pages, etc.)
- White pages / public records
- Historical lookup data
- Toll-free number company identification

### Implementation Approach

This skill uses **web search** as its primary investigation method, following Claude Code's web search capabilities. This approach:

- Requires no API keys or paid services
- Aggregates information from multiple public sources
- Provides transparency through source citations
- Respects platform terms of service
- Emphasizes privacy and ethical use

## Usage

### Activating the Skill

The skill is automatically available to Claude Code when placed in the skills directory. Simply ask Claude to investigate a phone number:

```
Investigate phone number +1-555-123-4567
```

```
Look up information for (415) 555-1212
```

```
Run phone OSINT on 202-456-1111
```

```
Check if +44 20 7183 8750 is spam
```

### Example Prompts

**Basic Investigation**:
```
Investigate phone number (555) 123-4567
```

**Spam Check Focus**:
```
Is phone number 800-555-0199 a scam? Check spam databases.
```

**VoIP Detection**:
```
Determine if +1-650-555-1234 is a VoIP number or mobile.
```

**International Number**:
```
Look up phone number +44 20 7183 8750 - what country and region?
```

**Comprehensive Report**:
```
Full OSINT report for phone number +1-202-555-0147 including location,
carrier, spam reports, and social media presence.
```

### Expected Output

The skill generates a comprehensive markdown report with sections:

1. **Phone Number Details** - Format, country, area code, line type, carrier
2. **Geographic Location** - Primary location, coverage area, time zone
3. **Spam/Scam Reports** - Risk assessment, report count, findings by source
4. **Social Media Presence** - Public associations (privacy-limited)
5. **Additional Information** - Business listings, public records
6. **Limitations & Disclaimers** - Privacy notices, accuracy warnings
7. **Sources Consulted** - Full list of URLs referenced

See `assets/output_template.md` for the complete report format.

## External Documentation and Resources

### OSINT Databases & Tools

**Spam/Scam Reporting Sites**:
- [RoboKiller Lookup](https://lookup.robokiller.com/) - Scam phone number database
- [YouMail Directory](https://directory.youmail.com/) - Spam call directory
- [SpamCalls.net](https://spamcalls.net/en/) - Global spam call database
- [800notes](http://800notes.com/) - User-reported call database
- [WhoCallsMe](https://whocallsme.com/) - Caller ID lookup
- [CallerSmart](https://www.callersmart.com/) - Spam call identification

**Area Code & Geographic Data**:
- [AllAreaCodes.com](https://www.allareacodes.com/) - NANP area code database
- [AreaCode.org](https://areacode.org/) - Area code locator and maps
- [NANPA.com](https://www.nationalnanpa.com/) - Official NANP administrator

**Carrier & Line Type**:
- [FreeCarrierLookup.com](https://www.freecarrierlookup.com/) - Basic carrier lookup
- Public telecom databases (via web search)

### Technical References

- [Google libphonenumber](https://github.com/google/libphonenumber) - Phone number parsing library
- [phonenumbers Python library](https://pypi.org/project/phonenumbers/) - Python implementation
- [ITU-T E.164](https://www.itu.int/rec/T-REC-E.164/) - International numbering plan

### OSINT Methodology

- [OSINT Framework](https://osintframework.com/) - OSINT tools and techniques
- [Bellingcat Toolkit](https://bellingcat.gitbook.io/toolkit/) - Investigative journalism tools
- [IntelTechniques](https://inteltechniques.com/) - OSINT training and tools

## Optional: Python Scripts

The `scripts/` directory contains optional Python tools that enhance phone number analysis. **These scripts are optional** - the skill's primary functionality uses web search and doesn't require running them.

### Available Scripts

#### 1. validate_phone.py

Parses and validates phone numbers using the `phonenumbers` library.

**Features**:
- Parse multiple phone number formats
- Extract country code, area code, national number
- Validate format (is_valid_number, is_possible_number)
- Determine number type (mobile/fixed-line/VoIP)
- Get geographic description, carrier (if available), timezone
- Format output in multiple styles (E.164, international, national, RFC3966)

**Usage**:
```bash
cd scripts/
python validate_phone.py "+1-555-123-4567"
python validate_phone.py "(555) 123-4567" --region US
python validate_phone.py "+44 20 7183 8750" --format json
```

**Example Output**:
```
============================================================
PHONE NUMBER ANALYSIS REPORT
============================================================

VALIDATION:
  Valid Number:        True
  Possible Number:     True

NUMBER COMPONENTS:
  Country Code:        +1
  National Number:     5551234567
  Area Code:           555
  Region Code:         US

NUMBER INFORMATION:
  Number Type:         Fixed Line or Mobile
  Geographic Location: United States
  Carrier:             Unknown
  Time Zone(s):        America/New_York

FORMATTED OUTPUT:
  E.164 Format:        +15551234567
  International:       +1 555-123-4567
  National:            (555) 123-4567
  RFC3966:             tel:+1-555-123-4567
============================================================
```

#### 2. area_code_lookup.py

Performs offline NANP area code geolocation lookups using a local CSV database.

**Features**:
- Load comprehensive NANP area code database (included)
- Lookup area code → city, state, country, coordinates, timezone
- Handle overlay area codes (multiple cities per code)
- No internet connection required (fully offline)
- No API keys needed

**Usage**:
```bash
cd scripts/
python area_code_lookup.py 415
python area_code_lookup.py 212 --format json
python area_code_lookup.py 310 --csv /custom/path/area_codes.csv
```

**Example Output**:
```
============================================================
AREA CODE LOOKUP: 415
============================================================

LOCATION:
  Area Code:      415
  Country:        USA
  State/Province: California
  City:           San Francisco
  Time Zone:      America/Los_Angeles
  Coordinates:    37.7749, -122.4194
============================================================
```

### Setup Instructions

1. **Install Python** (3.7 or higher)

2. **Create virtual environment** (recommended):
   ```bash
   cd scripts/
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run scripts**:
   ```bash
   python validate_phone.py "+1-555-123-4567"
   python area_code_lookup.py 415
   ```

### Dependencies

- **phonenumbers** (>=8.13.0) - Phone number parsing and validation
- **pandas** (>=1.5.0) - CSV database handling for area codes
- **requests** (>=2.31.0) - HTTP library (for future enhancements)

---

## ⚠️ ADVANCED: WhatsApp Account Verification (Unofficial)

**CRITICAL WARNING**: This functionality uses an **unofficial** WhatsApp library that **VIOLATES** WhatsApp's Terms of Service. Your account/phone number may be **PERMANENTLY BANNED**.

### Purpose

For **authorized corporate security investigations** only:
- BEC (Business Email Compromise) fraud investigations
- CEO impersonation/phishing attack attribution
- Smishing (SMS phishing) threat actor identification
- Fraud prevention and incident response

### Requirements

**Legal/Compliance**:
- ✅ Written authorization from Legal/Compliance department
- ✅ Documented security investigation use case
- ✅ Proper authorization form (template in WHATSAPP_SETUP.md)

**Technical**:
- Node.js 18+ installed
- Dedicated phone number (Google Voice recommended)
- Investigation phone with WhatsApp installed
- **NOT for use with personal accounts**

### What It Does

```bash
# Check if a phone number is registered on WhatsApp
node whatsapp_check.js "+1-937-536-1299"

# Output:
# WhatsApp Account: ✓ REGISTERED
# Display Name: [Name or "Unknown"]
# Business Account: Yes/No
```

### Quick Start

1. **Get Legal Approval** (REQUIRED)
2. **Set up dedicated Google Voice number** (free)
3. **Register WhatsApp** on investigation phone with that number
4. **Install dependencies**:
   ```bash
   cd scripts/
   npm install
   ```
5. **First-time pairing** (scan QR code with investigation phone)
6. **Run checks** as needed

### Full Documentation

**Complete setup guide**: [WHATSAPP_SETUP.md](WHATSAPP_SETUP.md)
- Step-by-step Google Voice setup
- WhatsApp registration and configuration
- OpSec best practices
- Legal considerations
- Troubleshooting

**Quick reference**: [WHATSAPP_QUICKSTART.md](WHATSAPP_QUICKSTART.md)
- Daily workflow for authorized investigators
- Common commands
- Batch checking scripts

### Operational Security

**DO**:
- ✅ Use dedicated Google Voice or burner number
- ✅ Use on isolated investigation workstation
- ✅ Document all checks (automatic logging)
- ✅ Rotate investigation numbers every 90 days
- ✅ Wait 5-10 seconds between checks (rate limiting)

**DO NOT**:
- ❌ Use personal WhatsApp accounts
- ❌ Use company executive phone numbers
- ❌ Check more than 20-30 numbers per day
- ❌ Use for unauthorized investigations
- ❌ Use on corporate production network

### Risks

- **Account Ban**: WhatsApp may permanently ban your investigation phone number
- **ToS Violation**: This uses unofficial APIs that violate WhatsApp Terms of Service
- **No Support**: No official support from Meta/WhatsApp
- **Breakage**: May stop working if WhatsApp updates their systems

### Alternatives (Official)

For production/long-term use, consider:
- **WhatsApp Business API** (official, ToS-compliant, paid)
- Manual verification (save contact, check in WhatsApp app)
- Third-party OSINT platforms with official integrations

### Log Files

All checks logged automatically:
```
logs/
├── whatsapp_investigations_2026-01-02.json  # Daily log
└── whatsapp_result_[timestamp].json         # Individual results
```

**Security**: Encrypt logs, limit access, retain per compliance policy (minimum 7 years recommended).

---

## ⚠️ ADVANCED: Telegram Account Verification (Unofficial)

**CRITICAL WARNING**: This functionality uses an **unofficial** Telegram library that **VIOLATES** Telegram's Terms of Service. Your account/phone number may be **PERMANENTLY BANNED**.

### Purpose

For **authorized corporate security investigations** only:
- BEC (Business Email Compromise) fraud investigations
- CEO impersonation/phishing attack attribution
- Smishing (SMS phishing) threat actor identification
- Fraud prevention and incident response

### Requirements

**Legal/Compliance**:
- ✅ Written authorization from Legal/Compliance department
- ✅ Documented security investigation use case
- ✅ Proper authorization form (template in TELEGRAM_SETUP.md)

**Technical**:
- Node.js 18+ installed
- Dedicated phone number (Google Voice recommended)
- Telegram API credentials (api_id and api_hash from https://my.telegram.org)
- Investigation Telegram account
- **NOT for use with personal accounts**

### What It Does

```bash
# Check if a phone number is registered on Telegram
node telegram_check.js "+1-937-536-1299"

# Output:
# Telegram Account: ✓ REGISTERED
# Username: @johndoe
# First Name: John
# Verified: No
# Premium: No
```

### Quick Start

1. **Get Legal Approval** (REQUIRED)
2. **Set up dedicated Google Voice number** (free)
3. **Register Telegram** on investigation workstation with that number
4. **Obtain Telegram API credentials**:
   - Go to https://my.telegram.org/auth
   - Login with investigation number
   - Click "API development tools"
   - Create app and save api_id and api_hash
5. **Install dependencies**:
   ```bash
   cd scripts/
   npm install
   ```
6. **First-time authentication** (enter API credentials, phone code, optional 2FA)
7. **Run checks** as needed

### Full Documentation

**Complete setup guide**: [TELEGRAM_SETUP.md](TELEGRAM_SETUP.md)
- Step-by-step Google Voice setup
- Obtaining Telegram API credentials
- Telegram registration and configuration
- OpSec best practices
- Legal considerations
- Troubleshooting

**Quick reference**: [TELEGRAM_QUICKSTART.md](TELEGRAM_QUICKSTART.md)
- Daily workflow for authorized investigators
- Common commands
- Batch checking scripts

### Operational Security

**DO**:
- ✅ Use dedicated Google Voice or burner number
- ✅ Use on isolated investigation workstation
- ✅ Document all checks (automatic logging)
- ✅ Rotate investigation numbers every 90 days
- ✅ Wait 5-10 seconds between checks (rate limiting)

**DO NOT**:
- ❌ Use personal Telegram accounts
- ❌ Use company executive phone numbers
- ❌ Check more than 20-30 numbers per day
- ❌ Use for unauthorized investigations
- ❌ Use on corporate production network

### Risks

- **Account Ban**: Telegram may permanently ban your investigation phone number
- **ToS Violation**: This uses unofficial APIs that violate Telegram Terms of Service
- **No Support**: No official support from Telegram
- **Breakage**: May stop working if Telegram updates their systems

### Alternatives (Official)

For production/long-term use, consider:
- **Telegram Bot API** (official, limited for this use case)
- Manual verification (add contact in Telegram app, check if profile appears)
- Third-party OSINT platforms with official integrations

### Log Files

All checks logged automatically:
```
logs/
├── telegram_investigations_2026-01-02.json  # Daily log
└── telegram_result_[timestamp].json         # Individual results
```

**Security**: Encrypt logs, limit access, retain per compliance policy (minimum 7 years recommended).

### Comparison: Telegram vs WhatsApp

| Feature | Telegram | WhatsApp |
|---------|----------|----------|
| **Setup Complexity** | Requires API credentials | QR code pairing only |
| **Authentication** | Phone code + optional 2FA | QR code scan |
| **Data Retrieved** | Username, verified status, premium status | Display name, business status |
| **Rate Limiting** | ~20-30 checks/day safe | ~20-30 checks/day safe |
| **Ban Risk** | Moderate | Moderate |

**Recommendation**: Use both tools for comprehensive messaging platform coverage in investigations.

---

## ⚠️ ADVANCED: Snapchat Account Verification (Manual Method)

**EXTREME RISK WARNING**: Snapchat has the **MOST AGGRESSIVE** anti-automation of any platform. Automated checking will almost certainly result in **PERMANENT ACCOUNT BAN** within hours/days.

**STRONG RECOMMENDATION: Use MANUAL verification ONLY** (documented below).

### Purpose

For **authorized corporate security investigations** only:
- BEC (Business Email Compromise) fraud investigations
- CEO impersonation/phishing attack attribution (especially younger demographics)
- Smishing (SMS phishing) threat actor identification
- Fraud prevention and incident response

### Why Manual Only?

Unlike WhatsApp and Telegram where automation is viable with caution, **Snapchat automation is NOT viable**:

| Aspect | Snapchat | WhatsApp/Telegram |
|--------|----------|-------------------|
| **Ban Risk** | 95%+ (almost certain) | 30-50% (moderate) |
| **Library Reliability** | < 20% (often broken) | ~80% (mostly working) |
| **ToS Enforcement** | Extremely aggressive | Moderate |
| **Detection Sophistication** | Very high (ML-based) | Medium |
| **Recommended Method** | ✅ Manual only | ⚠️ Automated with caution |

### Manual Verification Method (RECOMMENDED)

**What You Need**:
- Investigation phone with Snapchat app
- Snapchat account (Google Voice number)
- 4-5 minutes per check

**How It Works**:

```
STEP 1: Add phone number to investigation phone contacts (30 sec)

STEP 2: Open Snapchat → Add Friends → Contacts (30 sec)
        Contact sync will show if number has Snapchat account

STEP 3: If account exists, view profile details (1 min)
        - Username (e.g., @johndoe123)
        - Display Name
        - Bitmoji avatar
        - Snap Score
        - Public Stories (if available)
        DO NOT add them as friend (leaves trace)

STEP 4: Take screenshots and document findings (2 min)

STEP 5: Delete contact from phone (30 sec)

Total time: ~4-5 minutes per check
```

### Advantages of Manual Method

✅ **No Ban Risk**: Contact syncing is legitimate Snapchat feature
✅ **ToS Compliant**: No automation violations
✅ **100% Reliable**: Always works (no broken libraries)
✅ **More Data**: Can view Bitmoji, Stories, Snap Score
✅ **Sustainable**: Investigation account won't be banned

### Quick Start

1. **Get Legal Approval** (REQUIRED)
2. **Set up investigation phone**:
   - Install Snapchat app
   - Register with Google Voice number
   - Configure privacy settings:
     - Settings → "See Me in Quick Add": **OFF**
     - Settings → "Let Others Find Me": **OFF**
3. **Enable contact sync**: Settings → Permissions → Contacts: Allow
4. **Follow manual verification workflow** (see above)

### Full Documentation

**Complete setup guide**: [SNAPCHAT_SETUP.md](SNAPCHAT_SETUP.md)
- Manual verification step-by-step
- Privacy settings configuration
- Why automated checking fails
- Legal considerations
- Best practices

**Quick reference**: [SNAPCHAT_QUICKSTART.md](SNAPCHAT_QUICKSTART.md)
- 4-minute manual workflow
- Investigation templates
- Troubleshooting

### Automated Method (NOT RECOMMENDED)

An automated checking script (`snapchat_check.py`) is provided for completeness, but:

⚠️ **Extreme ban risk** (95%+ chance of permanent ban)
⚠️ **Often doesn't work** (libraries frequently broken)
⚠️ **Not worth the effort** (manual is faster when accounting for setup/debugging)

**Only consider automated if**:
- You need to check hundreds of numbers
- You accept investigation account will be banned
- You have technical expertise in reverse engineering

```bash
# Default: Shows manual verification guide
python snapchat_check.py "+1-555-123-4567"

# Force automated (NOT RECOMMENDED)
python snapchat_check.py "+1-555-123-4567" --force-automated
# Expected: Library errors or immediate account ban
```

### Rate Limiting (Manual Method)

Even manual checking needs limits:

- ⏱️ **5-10 checks per day** maximum
- 📊 **Wait 30-60 minutes** between checks
- 🔄 **Spread throughout day** (not all at once)
- 🗑️ **Delete contacts** after each check

### Operational Security

**DO**:
- ✅ Use dedicated investigation phone (not personal)
- ✅ Configure privacy settings (disable "Quick Add")
- ✅ Document with screenshots
- ✅ Delete contacts after verification
- ✅ Cross-reference with WhatsApp/Telegram

**DO NOT**:
- ❌ Add targets as friends (leaves permanent trace)
- ❌ Use automated tools (extreme ban risk)
- ❌ Sync many contacts at once
- ❌ Use personal Snapchat accounts

### Log Files

Manual verification logs:
```
logs/
├── snapchat_investigations_2026-01-02.json  # Daily log
└── snapchat_result_manual_[timestamp].json  # Individual results
```

Include screenshots: `snapchat_profile_[timestamp].png`

### Platform Coverage Summary

**Complete messaging platform investigation** (~5-6 minutes total):

| Platform | Method | Time | Reliability | Data Quality |
|----------|--------|------|-------------|--------------|
| WhatsApp | Automated | 30 sec | High | Medium |
| Telegram | Automated | 30 sec | High | High |
| **Snapchat** | **Manual** | **4-5 min** | **Very High** | **Very High** |

**Total**: ~5-6 minutes for comprehensive coverage across all three platforms.

### Why Snapchat Matters for Investigations

**Demographics**:
- Popular with 18-34 age group
- Common in consumer-facing fraud
- Used by social engineering attackers
- Often overlooked by investigators (opportunity for unique intelligence)

**Data Available**:
- Username (can be cross-referenced with other platforms)
- Display name (check for impersonation)
- Bitmoji (unique visual identifier)
- Snap Score (activity level - high score = established account)
- Verification badge (blue checkmark for notable accounts)
- Public Stories (attacker lifestyle/location clues)

**Investigation Value**:
- Younger threat actors more likely to have Snapchat than WhatsApp/Telegram
- Bitmoji provides visual confirmation (unique to Snapchat)
- Snap Score helps distinguish new vs. established accounts
- Public Stories may reveal attacker location/lifestyle

---

## Key Assets

### assets/ Directory

**area_codes.csv** - Comprehensive NANP area code database
- 400+ North American area codes (US, Canada, Caribbean)
- Geographic coordinates (latitude/longitude)
- Time zones for each area code
- State/province and major city mappings
- Regularly updated from public sources

**output_template.md** - Report format template
- Standard markdown template for OSINT reports
- Ensures consistent output formatting
- Includes all required sections and disclaimers

## references/ Directory

Advanced reference documentation loaded on-demand for complex investigations:

### OSINT_SOURCES.md
- Comprehensive list of free OSINT sources for phone numbers
- Detailed search techniques and query patterns
- Data reliability ratings for each source
- Best practices for multi-source verification

### PRIVACY.md
- Privacy laws (GDPR, CCPA, international regulations)
- Platform terms of service considerations
- Ethical guidelines for OSINT investigations
- Data handling best practices
- When to seek legal counsel

### LIMITATIONS.md
- Detailed technical limitations by data type
- Accuracy considerations for different number types
- Known edge cases and failure modes
- Cross-verification guidance
- What requires paid APIs vs. free sources

### API_GUIDE.md
- Optional paid APIs for enhanced lookups (reference only)
- Carrier lookup services (Twilio, NumVerify, etc.)
- Setup instructions and cost comparison
- API key management best practices
- Example integration code (not implemented in free version)

## Development Status

**Current Stage**: Development (v0.1)

**Recent Updates**:
- ✅ Initial skill implementation with YAML frontmatter
- ✅ Comprehensive 7-step OSINT investigation workflow
- ✅ Python validation scripts (validate_phone.py, area_code_lookup.py)
- ✅ NANP area code database with 400+ entries
- ✅ Free-sources-only approach (no API dependencies)
- ✅ Privacy-focused design with ethical guidelines

**Known Issues**:
- VoIP detection is approximate without paid APIs
- Social media checks are limited by platform privacy settings
- International number data less comprehensive than US/Canada
- Carrier information may be outdated due to number porting

**Testing Status**:
- ⏳ Needs testing with various phone number formats
- ⏳ Needs validation of web search query effectiveness
- ⏳ Needs testing with international numbers
- ⏳ Needs spam database search validation

## Limitations

### Technical Limitations

1. **Messaging Platform Access (WhatsApp, Telegram, Snapchat)**
   - **WhatsApp**: Does NOT allow phone number searches; manual verification only (save contact, check if profile appears)
   - **Telegram**: Restricts phone lookups; users can hide numbers from non-contacts; manual app check required
   - **Snapchat**: No phone number search feature; requires contact sync to verify accounts
   - **Web Search Limitation**: Can only find publicly posted references (e.g., "Contact me on WhatsApp: [number]")
   - **Privacy Protection**: Even if accounts exist, user details remain private unless verified manually within each app
   - **ToS Compliance**: Automated lookups or API scraping violate platform Terms of Service
   - Most users hide phone numbers from search via privacy settings

2. **Carrier Lookup Accuracy**
   - Free carrier data may be outdated
   - Number porting complicates carrier identification
   - VoIP detection not 100% reliable without paid APIs
   - Virtual numbers can mask true carrier

3. **Geographic Accuracy**
   - Area codes indicate general region, not exact location
   - Mobile numbers can be used anywhere (not tied to geography)
   - VoIP numbers can be assigned arbitrary area codes
   - Number portability means area code ≠ current location

4. **Spam/Scam Data**
   - Relies on user reports (subjective and incomplete)
   - New scam numbers won't have reports yet
   - Legitimate numbers can be falsely reported
   - Data freshness varies by source

5. **International Numbers**
   - Less comprehensive data outside US/Canada (NANP)
   - Country-specific databases may require local knowledge
   - Language barriers in non-English sources
   - Different privacy laws affect data availability

### Privacy & Legal Considerations

⚠️ **This skill is intended for legitimate investigative, security, or research purposes only.**

- **GDPR/CCPA Compliance**: Respect privacy laws when investigating numbers
- **Platform ToS**: Many social platforms prohibit automated phone lookups
- **Ethical Use**: Not for harassment, stalking, or unauthorized surveillance
- **Data Accuracy**: Information may be outdated; numbers can be reassigned
- **Caller ID Spoofing**: Displayed number ≠ actual caller (spoofing is common)

Always cross-verify findings from multiple sources before taking action.

### What Free Sources Cannot Provide

Without paid API services, the skill **cannot reliably**:

1. **Real-time Carrier Lookup** - Current carrier/line type requires paid services
2. **HLR/LRN Lookups** - Advanced telecom routing data needs commercial APIs
3. **Comprehensive Social Media** - No free APIs for bulk social media searches
4. **Live Number Validation** - Checking if number is currently active/in-service
5. **CNAM (Caller Name)** - Official caller name databases require carrier access
6. **International Deep Data** - Outside NANP, detailed data often requires payment

For these capabilities, see `references/API_GUIDE.md` for optional paid service options.

## Future Enhancements

Planned improvements for future versions:

**Version 0.2** (Testing & QA):
- Extensive testing with real-world phone numbers
- Validation of search query effectiveness
- Refinement of spam risk assessment algorithm
- International number testing and improvements

**Version 0.3** (Feature Enhancements):
- Batch processing for multiple phone numbers
- Historical data tracking (monitor number over time)
- Enhanced reporting with visualizations
- Export to JSON/CSV for analysis tools

**Version 1.0** (Production):
- Full validation and accuracy testing
- Comprehensive error handling
- Performance optimizations
- Optional API integrations (for users with API keys)
- Multi-language support for international numbers

**Future Considerations**:
- Integration with threat intelligence feeds
- Machine learning for spam pattern detection
- Blockchain-based caller verification checks
- Integration with email/IP OSINT skills

## Use Cases

### Security & Incident Response
- Investigating suspicious calls/texts (vishing, smishing)
- Verifying identity during security incidents
- Fraud investigation and prevention
- Threat actor attribution
- Phishing campaign analysis

### Business & Verification
- Verifying business contact information
- Customer due diligence checks
- Vendor validation
- Partner verification
- Call-back validation

### Research & Analysis
- Telecommunications research
- Spam/scam pattern analysis
- Geographic distribution studies
- Carrier infrastructure analysis
- Security awareness training

### Personal Safety
- Identifying unknown callers
- Blocking spam/scam numbers
- Verifying contacts before callbacks
- Personal safety investigations

## Getting Help

### Troubleshooting

**Issue**: Phone number not parsing correctly
- **Solution**: Try adding country code (+1 for US/Canada)
- **Solution**: Remove all formatting and retry
- **Solution**: Use the validate_phone.py script to test parsing

**Issue**: No spam reports found
- **Solution**: This is normal for many numbers (not all are reported)
- **Solution**: Try alternative search queries manually
- **Solution**: Check if number is new/recently assigned

**Issue**: Scripts not running
- **Solution**: Ensure Python 3.7+ is installed
- **Solution**: Check dependencies are installed: `pip install -r requirements.txt`
- **Solution**: Verify you're in the correct directory

**Issue**: Area code lookup fails
- **Solution**: Verify area_codes.csv exists in assets/ directory
- **Solution**: Check CSV file isn't corrupted
- **Solution**: Try specifying CSV path with --csv flag

### Support

For issues, bugs, or feature requests:
- **Project**: pksecure_io-claude skills repository
- **Author**: Paul Kincaid <paul@pksecure.io>
- **Documentation**: See references/ directory for detailed guides

### Contributing

This skill is part of a development repository. Contributions and feedback are welcome:
- Test with various phone number formats and report issues
- Suggest additional OSINT sources to include
- Improve search query effectiveness
- Enhance privacy and ethical use guidelines

## License

Apache License 2.0

Copyright (c) 2025 Paul Kincaid

Licensed under the Apache License, Version 2.0. You may obtain a copy at:
http://www.apache.org/licenses/LICENSE-2.0

---

**Disclaimer**: This OSINT tool is provided for lawful investigative, security research, and educational purposes. Users are responsible for ensuring their use complies with applicable laws and regulations. Always respect privacy rights and platform terms of service.

**Last Updated**: 2026-01-02
