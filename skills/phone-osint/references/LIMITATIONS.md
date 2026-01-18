# Phone Number OSINT - Known Limitations & Accuracy Considerations

This document details the technical limitations, accuracy considerations, and known edge cases for phone number OSINT investigations using free/public sources.

**Last Updated**: 2026-01-02

---

## Table of Contents

1. [Technical Limitations](#technical-limitations)
2. [Data Accuracy Considerations](#data-accuracy-considerations)
3. [Geographic Limitations](#geographic-limitations)
4. [Social Media Limitations](#social-media-limitations)
5. [Carrier & Line Type Limitations](#carrier--line-type-limitations)
6. [Spam Database Limitations](#spam-database-limitations)
7. [International Number Limitations](#international-number-limitations)
8. [Known Edge Cases](#known-edge-cases)
9. [Free vs. Paid API Capabilities](#free-vs-paid-api-capabilities)
10. [Cross-Verification Strategies](#cross-verification-strategies)

---

## Technical Limitations

### 1. No Real-Time Validation

**Limitation**: Free sources cannot verify if a phone number is currently active or in service.

**Why**: Real-time HLR (Home Location Register) lookups require carrier-level access or paid APIs.

**Impact**:
- Cannot confirm if number is currently active
- Cannot detect if number was recently disconnected
- Cannot verify if SMS/calls will be delivered

**Workaround**:
- Check for recent activity in spam databases (recent reports = likely active)
- Search for recent mentions online
- Note: Absence of activity ≠ inactive number

**Confidence Level**: Cannot determine with free sources

---

### 2. Limited Carrier Information

**Limitation**: Carrier data from free sources is often outdated or unavailable.

**Why**:
- Number portability (users can change carriers while keeping number)
- Free databases rely on initial assignments, not current carrier
- Carrier information requires live lookup APIs (paid services)

**Impact**:
- "Carrier: Unknown" in many cases
- Outdated carrier information (e.g., number ported from Verizon to T-Mobile, but shows Verizon)
- Cannot reliably distinguish between carriers

**Workaround**:
- Use as rough estimate only
- Note uncertainty in reports
- Web search may find user-reported carrier info

**Confidence Level**: Low (⭐⭐) for free sources

---

### 3. Approximate VoIP Detection

**Limitation**: Detecting VoIP numbers without paid APIs is unreliable.

**Why**:
- VoIP numbers can mimic regular mobile/landline numbers
- No public database comprehensively tracks VoIP assignments
- Many VoIP providers use standard NANP numbers indistinguishable from landlines

**Impact**:
- "Line Type: Unknown" or "Fixed Line" (which may actually be VoIP)
- Cannot reliably identify Google Voice, Skype, or other VoIP services
- False negatives (VoIP identified as landline)

**Workaround**:
- Search for "[number] Google Voice" or "[number] VoIP"
- Check spam databases (VoIP often used for scams, may be reported)
- Note: Certain area code + prefix combinations are known VoIP blocks (research required)

**Confidence Level**: Low (⭐⭐) for free sources

---

### 4. Social Media Access Restricted

**Limitation**: Most social media platforms block phone number searches for privacy.

**Why**:
- Privacy laws (GDPR, CCPA) require platforms to protect user data
- Terms of Service prohibit automated lookups
- API access restricted to authorized applications
- User privacy settings hide phone numbers

**Impact**:
- Very limited results from social media searches
- Cannot directly lookup "who owns this phone number" on WhatsApp/Telegram
- Most searches find only publicly posted references to numbers (not profiles)

**Workaround**:
- Search for publicly posted contact information
- Check business pages (may list phone numbers)
- Search for mentions of the number in posts/tweets
- LinkedIn may show professional contact info if public

**Confidence Level**: Very Low (⭐) - expect minimal results

---

### 5. No Comprehensive Call History

**Limitation**: Cannot access call logs, call history, or CDRs (Call Detail Records).

**Why**:
- Call records are private, held by carriers
- Require subpoena or warrant for law enforcement access
- Not available through public sources

**Impact**:
- Cannot determine who called/texted whom
- Cannot see frequency or timing of calls
- Cannot track communication patterns

**Workaround**:
- None for free sources
- Law enforcement can obtain with proper legal process

**Confidence Level**: Not Available

---

### 6. Rate Limiting & Blocking

**Limitation**: Excessive searches may trigger rate limits or blocking.

**Why**:
- Search engines and websites have anti-bot measures
- Excessive queries flagged as automated scraping
- CAPTCHAs or IP blocks triggered

**Impact**:
- Searches may be temporarily blocked
- CAPTCHA challenges interrupt workflow
- IP address may be banned

**Workaround**:
- Space out searches (don't automate)
- Use different search engines
- Respect robots.txt and rate limits
- Use VPN if IP is blocked (check ToS first)

**Confidence Level**: N/A - operational issue

---

## Data Accuracy Considerations

### 1. Number Portability Issues

**Problem**: Phone numbers can be ported (transferred) between carriers.

**Impact**:
- Carrier information may show original carrier, not current
- Area code may not reflect current location (mobile numbers especially)
- Historical data may be inaccurate

**Example**:
- Number originally assigned to Verizon in New York
- User ported to T-Mobile and moved to California
- Free database still shows "Verizon, New York"

**Mitigation**:
- Note in reports: "Carrier data may be outdated due to number porting"
- Cross-check with recent spam reports (may mention current carrier)
- Don't rely solely on carrier data for critical decisions

**Error Rate**: High (30-50% of mobile numbers have been ported at some point)

---

### 2. Number Reassignment

**Problem**: Phone numbers are recycled and reassigned to new users.

**Impact**:
- Historical data may refer to previous owner
- Spam reports may be from old assignment
- Social media links may be outdated

**Timeline**:
- US: Numbers typically held 90 days after disconnection, then reassigned
- High churn: Popular area codes reassign numbers quickly

**Example**:
- Number assigned to business in 2020, reports show legitimate
- Business closed, number disconnected in 2023
- Number reassigned to scammer in 2024
- Current use: scam, but old data shows legitimate business

**Mitigation**:
- Check dates on all data sources
- Prefer recent data (< 6 months)
- Note: "Information may be outdated if number was reassigned"
- Look for timeline inconsistencies (e.g., business listing from 2020, spam reports from 2025)

**Error Rate**: Moderate (10-20% of numbers reassigned within 2 years of disconnection)

---

### 3. Caller ID Spoofing

**Critical Issue**: Caller ID can be easily spoofed (faked).

**Impact**:
- The number displayed on caller ID ≠ actual caller
- Scammers routinely spoof legitimate numbers
- Investigating spoofed number gives info about victim, not scammer

**How Spoofing Works**:
- VoIP services allow setting arbitrary caller ID
- Scammers use legitimate-looking numbers
- Often spoof local area codes ("neighbor spoofing")

**Example**:
- Scammer calls from India, spoofs +1-202-555-0199
- Victim sees "Washington, DC" caller ID
- Investigating 202-555-0199 reveals nothing about actual caller

**Mitigation**:
- **Always note**: "Caller ID can be spoofed. This number may not be the actual caller."
- Look for inconsistencies (e.g., "caller had foreign accent but number is US")
- Check if number is reported as spoofed in spam databases
- Don't assume displayed number = actual caller

**Prevalence**: Extremely common in scam calls (50-80% of scam calls use spoofing)

---

### 4. User-Reported Data Subjectivity

**Problem**: Spam databases rely on subjective user reports.

**Impact**:
- Legitimate businesses may be falsely reported
- Personal grudges may result in false reports
- Telemarketing (legal) reported as "scam"
- Volume of reports ≠ accuracy

**Example**:
- Debt collection agency (legitimate, regulated)
- Users report as "scam" because they don't want to pay debt
- Database shows high spam score, but it's actually legitimate business

**Mitigation**:
- Read user comments, not just spam scores
- Look for specific details (e.g., "IRS impersonation scam" vs. "annoying call")
- Assess volume: 100+ consistent reports more reliable than 2-3
- Cross-check with business directories (is this a real company?)

**False Positive Rate**: Moderate (10-30% of reports may be false/subjective)

---

### 5. Data Freshness Varies

**Problem**: Update frequency varies widely by source.

**Impact**:
- Some sources updated in real-time (spam databases)
- Others updated rarely (carrier databases, area code assignments)
- Mixed data ages in reports

**Source Update Frequencies**:
- Spam databases: Real-time to daily
- Area codes: As new codes assigned (rare)
- Carrier databases (free): Months to years outdated
- Social media: Variable (depends on user updates)

**Mitigation**:
- Check "last updated" or date on sources
- Prefer recent data
- Note data age in reports
- Re-investigate if information is old

**Recommendation**: Re-investigate every 6 months for active cases

---

## Geographic Limitations

### 1. Area Code ≠ Current Location

**Limitation**: Area codes indicate where number was assigned, not where user is now.

**Why**:
- Mobile numbers can be used anywhere
- Number portability allows keeping number when moving
- VoIP numbers can have arbitrary area codes

**Impact**:
- 415 area code (San Francisco) user may be in New York
- Cannot determine user's current location from area code
- Geographic data is general region only

**Example**:
- User gets 650 (California) number in 2015
- Moves to Texas in 2020, keeps same number
- OSINT shows "California" but user is in Texas

**Mitigation**:
- Note: "Area code indicates original assignment, not current location"
- For mobile/VoIP: "User could be anywhere"
- Only landlines reliably indicate location

**Accuracy**: High for landlines (⭐⭐⭐⭐), Very Low for mobile/VoIP (⭐)

---

### 2. Overlay Area Codes

**Problem**: Multiple area codes cover the same geographic region.

**Impact**:
- Cannot distinguish between overlays without additional data
- Area code alone doesn't narrow down location sufficiently

**Example**:
- Los Angeles has 213, 323, 310, 424, 747, 818 area codes
- All cover overlapping regions
- Cannot determine specific neighborhood from area code

**Mitigation**:
- Report all overlay codes for the region
- Note: "This area code is part of an overlay with [other codes]"
- Provide general region, not specific location

---

### 3. International Number Data Gaps

**Limitation**: Non-NANP (international) numbers have less comprehensive free data.

**Why**:
- Most free databases focus on US/Canada (NANP)
- International phone systems vary widely
- Language barriers in non-English sources
- Different privacy laws affect data availability

**Impact**:
- Limited carrier information for international numbers
- Less spam data outside US/EU
- Geographic data may be country-level only (no region/city)

**Workaround**:
- Use country-specific OSINT sources
- Wikipedia for country code information
- International spam databases (e.g., SpamCalls.net for Europe)

**Accuracy**: Moderate for EU/UK (⭐⭐⭐), Low for other regions (⭐⭐)

---

## Social Media Limitations

### 1. Platform Privacy Settings

**Limitation**: Most users hide phone numbers via privacy settings.

**Impact**:
- Even if number is registered on platform, it's not publicly visible
- Search results show only users who made numbers public (rare)
- Most social media searches return zero results

**Example**:
- User's Facebook profile has phone number
- Privacy setting: "Only Me" can see phone number
- OSINT search finds nothing (profile is hidden)

**Workaround**:
- Check business/public figure pages (may list contact info)
- Search for public posts mentioning the number

**Success Rate**: Very Low (< 5% of numbers findable on social media)

---

### 2. Terms of Service Restrictions

**Limitation**: Automated phone number lookups violate most platform ToS.

**Impact**:
- Cannot legally use APIs for bulk lookups
- Manual searches only (slow, limited)
- Risk of account suspension if detected

**Prohibited**:
- WhatsApp: Automated checks if number registered
- Telegram: Bulk username lookups by phone
- Facebook/LinkedIn: Phone number graph searches

**Workaround**:
- Manual, one-off searches (within ToS)
- Search for public references to number (not direct profile lookup)

---

### 3. International Platform Variations

**Limitation**: Platform popularity varies by region.

**Impact**:
- WhatsApp dominant in Europe/South America, less in US
- WeChat critical in China, unavailable/blocked elsewhere
- Telegram popular in Russia/Eastern Europe

**Implication**: Need to know which platforms are used in target region

---

## Carrier & Line Type Limitations

### 1. Fixed Line vs. VoIP Ambiguity

**Problem**: "Fixed Line" often means VoIP, not traditional landline.

**Why**:
- Phonenumbers library categorizes VoIP as "Fixed Line or Mobile"
- Many free databases don't distinguish VoIP from landline
- Modern "landlines" are often VoIP (cable companies)

**Impact**:
- "Fixed Line" result is ambiguous
- Cannot reliably distinguish true POTS landline from VoIP

**Example**:
- Google Voice number shows "Fixed Line"
- Comcast cable phone shows "Fixed Line"
- Traditional copper landline shows "Fixed Line"
- All are different technologies, but same label

**Mitigation**:
- Note: "Fixed Line may indicate VoIP"
- Search specifically for VoIP indicators
- True POTS landlines are rare in modern times

---

### 2. Prepaid vs. Postpaid Unknown

**Limitation**: Cannot distinguish prepaid from postpaid accounts.

**Why**: This information is carrier-internal, not public

**Impact**: Cannot assess if number is "burner phone" (prepaid, disposable)

---

### 3. MVNO (Mobile Virtual Network Operator) Complexity

**Problem**: MVNOs (e.g., Cricket, Metro PCS) use parent carrier networks.

**Impact**:
- Number may show parent carrier (AT&T, T-Mobile) instead of MVNO
- Or may show MVNO when technical carrier is parent
- Inconsistent across databases

**Example**:
- Cricket Wireless (MVNO using AT&T network)
- May show as "AT&T" or "Cricket" depending on source

---

## Spam Database Limitations

### 1. New Number Gap

**Limitation**: New scam numbers have no reports initially.

**Impact**:
- Zero spam reports ≠ legitimate number
- Scammers change numbers frequently
- New scam campaign numbers won't show in databases yet

**Timeline**:
- Scam number activated Monday
- First victims Tuesday-Wednesday
- Reports appear in databases Thursday-Friday
- Scammer may already switch to new number by Friday

**Mitigation**:
- Note: "No reports may indicate new number, not necessarily legitimate"
- Check other indicators (VoIP, spoofed caller ID, etc.)

---

### 2. Legitimate Business False Positives

**Problem**: Aggressive but legal businesses get reported as spam.

**Examples**:
- Debt collectors (legal, regulated, but unwanted calls)
- Telemarketers (legal if on business call lists)
- Political campaigns (exempt from Do Not Call)
- Survey companies

**Impact**:
- High spam scores don't always mean scam
- Need to distinguish "unwanted but legal" from "illegal scam"

**Mitigation**:
- Read user comments for context
- Check if business is registered/legitimate
- Distinguish between "spam" and "scam"

---

### 3. Report Volume Bias

**Problem**: Popular scam numbers get many reports; smaller operations get few.

**Impact**:
- Large-scale robocall campaigns: thousands of reports
- Targeted scams (e.g., business email compromise): few reports
- Low report count ≠ not a scam

**Mitigation**:
- Don't require high report count for concern
- Even 1-2 detailed scam reports should be noted

---

## International Number Limitations

### 1. Country Code Coverage Gaps

**Good Coverage** (⭐⭐⭐⭐):
- +1 (US, Canada) - NANP
- +44 (UK)
- +61 (Australia)
- +49 (Germany)
- Major Western European countries

**Moderate Coverage** (⭐⭐⭐):
- +81 (Japan)
- +82 (South Korea)
- +91 (India)
- +86 (China) - note: firewall limits access

**Poor Coverage** (⭐⭐):
- Africa (most countries)
- South America (except Brazil)
- Central Asia
- Middle East (varies)

---

### 2. Language Barriers

**Problem**: Non-English spam reports difficult to interpret.

**Impact**:
- Russian spam databases in Cyrillic
- Chinese sources behind Great Firewall
- Portuguese/Spanish sources for Latin America

**Workaround**:
- Google Translate on web pages
- Use English-language international sources (SpamCalls.net)

---

### 3. Different Numbering Plans

**Complexity**: Not all countries use simple country code + area code + number format.

**Examples**:
- UK: Complex area codes, varying lengths
- France: Mobile vs. landline by first digits
- Germany: City codes vary in length

**Impact**:
- Parsing may be less accurate
- Area code lookup may not work
- Phonenumbers library handles this, but free sources may not

---

## Known Edge Cases

### 1. Toll-Free Numbers

**Special Considerations**:
- Toll-free (800, 888, 877, 866, 855, 844, 833) are not geographically tied
- Company can be anywhere
- Often used by large corporations, call centers, scammers

**OSINT Approach**:
- Search for company name, not location
- Check 800notes for company identification
- Note: "Toll-free number, no geographic association"

---

### 2. Short Codes (5-6 digits)

**Limitation**: Short codes (e.g., 12345 for SMS) are not phone numbers.

**Impact**:
- Not searchable in phone databases
- Different registration system (CTIA Short Code Registry)
- Often legitimate (banks, services) but scams exist

**OSINT Approach**:
- Search "[short code] SMS scam"
- Check CTIA Short Code Registry (legitimate businesses)

---

### 3. International Format Confusion

**Problem**: Same number written different ways.

**Example**:
- +1-415-555-1212 (E.164 international)
- (415) 555-1212 (US national)
- 1-415-555-1212 (US with country code)
- 14155551212 (no formatting)

**Impact**:
- Search for one format may miss results in another
- Need to search multiple formats

**Mitigation**:
- Use validate_phone.py to get all formats
- Search for multiple formats in web searches

---

### 4. Numbers in Text (Context Matters)

**Problem**: Finding a number online doesn't mean it's linked to that content.

**Example**:
- Forum post: "I got a scam call from 555-1212"
- Number is mentioned, but poster is victim, not scammer
- OSINT search finds post, but misattributes connection

**Mitigation**:
- Read context carefully
- Distinguish between "this number called me" vs. "this is my number"

---

## Free vs. Paid API Capabilities

### What Free Sources Can Do

✅ Basic validation (format, possible/valid number)
✅ Area code geographic lookup (NANP)
✅ Country code identification
✅ Spam/scam report aggregation
✅ Basic number type (mobile/landline/toll-free) - approximate
✅ Business directory lookups
✅ Public social media mentions

### What Requires Paid APIs

❌ **Real-time carrier lookup** - Current carrier, not original assignment
❌ **Live number validation** - Is number currently active/in-service
❌ **HLR/LRN queries** - Home Location Register, Local Routing Number
❌ **Caller Name (CNAM) lookup** - Official caller ID name
❌ **Porting history** - When number was ported, to which carriers
❌ **Number type (high accuracy)** - Definitive mobile/landline/VoIP
❌ **Prepaid vs. postpaid** - Account type
❌ **Roaming status** - Where phone currently is (location-based)
❌ **SMS delivery validation** - Can SMS be delivered
❌ **Reputation scores** - Fraud risk scoring

### Cost Comparison (Estimated)

**Free Sources**: $0

**Paid APIs** (per lookup):
- Basic validation: $0.001 - $0.01
- Carrier lookup: $0.01 - $0.05
- HLR query: $0.02 - $0.10
- CNAM lookup: $0.01 - $0.02
- Advanced validation: $0.05 - $0.20

**Monthly Subscription** (some providers):
- Basic tier: $10-50/month (1,000-10,000 lookups)
- Professional: $100-500/month (unlimited or high volume)

---

## Cross-Verification Strategies

### How to Compensate for Limitations

#### 1. Multi-Source Verification

**Strategy**: Use 3+ independent sources for critical information.

**Example**:
- Spam Check: RoboKiller + YouMail + 800notes
- Geographic: Area code database + Wikipedia + Whitepages
- Business: Yellow Pages + Google + LinkedIn

**Benefit**: Reduces error rate, increases confidence

---

#### 2. Temporal Verification

**Strategy**: Check for timeline consistency.

**Questions to Ask**:
- When was this information last updated?
- Are there reports from multiple time periods?
- Is there a sudden change in reports (may indicate reassignment)?

**Example**:
- 2018-2022: Reports show "ABC Company customer service"
- 2023-2025: Reports show "IRS scam"
- **Conclusion**: Number likely reassigned, current use is scam

---

#### 3. Context Analysis

**Strategy**: Read full context, not just summaries.

**Technique**:
- Read user comments in spam databases
- Check original sources (don't rely on aggregators)
- Look for specific details (names, tactics, scripts)

**Example**:
- Generic: "Spam call" (low information)
- Specific: "Caller claimed to be from IRS, demanded iTunes gift cards" (high information, clear scam)

---

#### 4. Inverse Verification

**Strategy**: Search for disconfirming evidence.

**Technique**:
- Search "[number] legitimate" or "[number] not spam"
- Check if it's a known business
- Look for official company websites listing the number

**Benefit**: Avoids confirmation bias, finds false positives

---

#### 5. Pattern Analysis

**Strategy**: Look for patterns across findings.

**Examples**:
- VoIP number + no carrier info + recent spam reports = likely scam
- Landline + business directory listing + no spam reports = likely legitimate
- Mobile + consistent company mentions + moderate spam = telemarketer

**Benefit**: Holistic assessment, not single data points

---

## Summary: Working Within Limitations

### Key Principles

1. **Acknowledge Uncertainty**
   - Use qualifiers: "likely", "possibly", "appears to be"
   - Provide confidence levels
   - Note limitations explicitly

2. **Prefer Recent Data**
   - Prioritize data < 6 months old
   - Flag outdated information
   - Re-verify periodically

3. **Cross-Verify Everything**
   - Never rely on single source
   - Use 3+ independent sources
   - Check for consistency

4. **Read Context Carefully**
   - Don't just skim summaries
   - Understand what data actually shows
   - Distinguish correlation from causation

5. **Document Limitations**
   - List what you couldn't determine
   - Note data gaps in reports
   - Explain why certain info unavailable

6. **Use Appropriate Confidence Levels**
   - High: 3+ reliable sources agree, recent data
   - Medium: 2 sources or mixed reliability
   - Low: Single source or outdated data
   - Unknown: No reliable information available

### When to Recommend Paid Services

Suggest paid APIs when:
- Client needs real-time carrier validation
- High-stakes decision (fraud investigation, litigation)
- Volume of lookups justifies subscription
- Free sources provide insufficient data

**Never**: Overstate free source capabilities to avoid paid options

---

**Document Version**: 1.0
**Last Updated**: 2026-01-02
**Maintained By**: Paul Kincaid <paul@pksecure.io>
