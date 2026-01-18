# OSINT Sources for Phone Number Investigations

This reference document provides comprehensive information about free OSINT sources for phone number investigations, including search techniques, data reliability ratings, and best practices.

**Last Updated**: 2026-01-02

---

## Table of Contents

1. [Spam & Scam Databases](#spam--scam-databases)
2. [Area Code & Geographic Data](#area-code--geographic-data)
3. [Carrier & Line Type Lookup](#carrier--line-type-lookup)
4. [Social Media & Professional Networks](#social-media--professional-networks)
5. [Public Records & Directories](#public-records--directories)
6. [Search Engine Techniques](#search-engine-techniques)
7. [Data Reliability Ratings](#data-reliability-ratings)
8. [Multi-Source Verification](#multi-source-verification)

---

## Spam & Scam Databases

### Primary Sources

#### 1. RoboKiller Lookup
- **URL**: https://lookup.robokiller.com/
- **Type**: User-reported spam call database
- **Coverage**: US/Canada focus, some international
- **Data Points**: Spam score, scam type, report count, user comments
- **Reliability**: ⭐⭐⭐⭐ (High - large user base)
- **Update Frequency**: Real-time user reports
- **Search Query**: `"[phone number]" site:robokiller.com`

**Best For**:
- Recent scam activity detection
- Spam score assessment
- Understanding scam tactics

**Limitations**:
- Requires significant report volume to appear
- False positives possible from legitimate businesses

#### 2. YouMail Spam Directory
- **URL**: https://directory.youmail.com/
- **Type**: Robocall and spam call directory
- **Coverage**: US/Canada, extensive database
- **Data Points**: Caller type, spam category, call frequency, user ratings
- **Reliability**: ⭐⭐⭐⭐ (High - millions of users)
- **Update Frequency**: Real-time automated + user reports
- **Search Query**: `"[phone number]" site:youmail.com`

**Best For**:
- Robocall identification
- Spam category classification
- Tracking call frequency patterns

**Limitations**:
- Focus on robocalls, may miss manual scam calls
- Geographic bias toward US

#### 3. SpamCalls.net
- **URL**: https://spamcalls.net/en/
- **Type**: Global spam phone number database
- **Coverage**: International (better for Europe)
- **Data Points**: Country, spam type, report date, user comments
- **Reliability**: ⭐⭐⭐ (Moderate - smaller but international)
- **Update Frequency**: User-reported, varies by region
- **Search Query**: `"[phone number]" site:spamcalls.net`

**Best For**:
- International number investigations
- European phone numbers
- Multilingual spam reports

**Limitations**:
- Smaller database than US-focused sites
- Report quality varies

#### 4. 800notes
- **URL**: http://800notes.com/
- **Type**: Reverse phone lookup with user comments
- **Coverage**: US/Canada, focus on toll-free and telemarketers
- **Data Points**: Company name, complaint type, detailed user stories
- **Reliability**: ⭐⭐⭐⭐ (High - extensive user comments)
- **Update Frequency**: Continuous user submissions
- **Search Query**: `"[phone number]" site:800notes.com`

**Best For**:
- Toll-free number identification
- Detailed user experiences
- Company verification

**Limitations**:
- Can be overly negative (people report complaints more than positive)
- Older platform, some outdated entries

#### 5. WhoCallsMe
- **URL**: https://whocallsme.com/
- **Type**: Community-driven caller ID
- **Coverage**: US/Canada primary
- **Data Points**: Caller name, type, user ratings, comments
- **Reliability**: ⭐⭐⭐ (Moderate)
- **Update Frequency**: User-submitted
- **Search Query**: `"[phone number]" site:whocallsme.com`

**Best For**:
- Community perspectives
- Anonymous caller identification
- Harassment tracking

**Limitations**:
- Smaller database
- Quality varies

#### 6. CallerSmart
- **URL**: https://www.callersmart.com/
- **Type**: Crowdsourced caller ID and spam blocking
- **Coverage**: US focus
- **Data Points**: Spam likelihood, caller type, blocking recommendations
- **Reliability**: ⭐⭐⭐ (Moderate)
- **Update Frequency**: Real-time app users + web reports
- **Search Query**: `"[phone number]" site:callersmart.com`

**Best For**:
- Mobile app integration data
- Spam likelihood scores
- Blocking decisions

**Limitations**:
- Requires app for full features
- Smaller web database

### Search Techniques for Spam Databases

**Basic Search Pattern**:
```
"[phone number]" spam scam reports
```

**Multi-Site Search**:
```
"[phone number]" site:robokiller.com OR site:youmail.com OR site:spamcalls.net
```

**Specific Scam Type**:
```
"[phone number]" phishing OR vishing OR smishing
"[phone number]" IRS scam OR tech support scam
```

**Date-Restricted Search** (for recent activity):
```
"[phone number]" spam after:2025-01-01
```

**User Experience Search**:
```
"[phone number]" "called me" OR "received call" scam
```

---

## Area Code & Geographic Data

### Primary Sources

#### 1. AllAreaCodes.com
- **URL**: https://www.allareacodes.com/
- **Type**: NANP area code database and lookup
- **Coverage**: US, Canada, Caribbean (all NANP regions)
- **Data Points**: State/province, cities, counties, time zones, map coverage
- **Reliability**: ⭐⭐⭐⭐⭐ (Very High - official NANP data)
- **Update Frequency**: Updated with new area codes from NANPA
- **Search Query**: `"[area code]" site:allareacodes.com location`

**Best For**:
- Authoritative area code data
- Coverage maps
- New area code information

**Limitations**:
- NANP only (no international)

#### 2. AreaCode.org
- **URL**: https://areacode.org/
- **Type**: Area code locator with maps
- **Coverage**: NANP (US/Canada focus)
- **Data Points**: State, primary cities, overlay codes, time zone
- **Reliability**: ⭐⭐⭐⭐ (High)
- **Update Frequency**: Regular updates
- **Search Query**: `"area code [code]" site:areacode.org`

**Best For**:
- Visual area code maps
- Overlay area code identification
- Quick reference

**Limitations**:
- Less detailed than AllAreaCodes
- NANP only

#### 3. NANPA (North American Numbering Plan Administration)
- **URL**: https://www.nationalnanpa.com/
- **Type**: Official NANP authority
- **Coverage**: All NANP regions (authoritative)
- **Data Points**: Official area code assignments, planning letters, exhaust dates
- **Reliability**: ⭐⭐⭐⭐⭐ (Authoritative source)
- **Update Frequency**: Real-time official updates
- **Search Query**: Direct site navigation required

**Best For**:
- Official verification
- New area code planning information
- Regulatory data

**Limitations**:
- Less user-friendly interface
- Technical data focus

#### 4. Wikipedia Area Code Lists
- **URL**: https://en.wikipedia.org/wiki/List_of_North_American_Numbering_Plan_area_codes
- **Type**: Comprehensive area code encyclopedia
- **Coverage**: NANP + international summaries
- **Data Points**: History, geography, overlays, special codes
- **Reliability**: ⭐⭐⭐⭐ (High - well-maintained)
- **Update Frequency**: Community-maintained, frequent updates
- **Search Query**: `"area code [code]" site:wikipedia.org`

**Best For**:
- Historical context
- Overlay area code information
- International overviews

**Limitations**:
- Not always real-time
- Varying detail by area code

### Search Techniques for Geographic Data

**Basic Area Code Search**:
```
"area code [XXX]" location city state
```

**Coverage Area Search**:
```
"area code [XXX]" coverage area cities counties
```

**Time Zone Search**:
```
"area code [XXX]" time zone
```

**Overlay Area Code Search**:
```
"area code [XXX]" overlay [YYY]
```

**NPA (Numbering Plan Area) Search**:
```
"NPA [XXX]" geographic region assignment
```

---

## Carrier & Line Type Lookup

### Free Sources (Limited Accuracy)

#### 1. FreeCarrierLookup.com
- **URL**: https://www.freecarrierlookup.com/
- **Type**: Free carrier identification service
- **Coverage**: US/Canada
- **Data Points**: Carrier name, line type (mobile/landline)
- **Reliability**: ⭐⭐⭐ (Moderate - may be outdated)
- **Update Frequency**: Varies, not real-time
- **Search Query**: `"[phone number]" carrier lookup`

**Best For**:
- Quick carrier identification
- Basic line type determination

**Limitations**:
- Data may be outdated due to number porting
- Limited detail

#### 2. Web Search for Carrier
- **Type**: Search engine investigation
- **Coverage**: Universal
- **Data Points**: Varies by source
- **Reliability**: ⭐⭐ (Low - highly variable)
- **Update Frequency**: N/A
- **Search Query**: `"[phone number]" carrier OR operator mobile wireless`

**Best For**:
- Finding mentions of carrier in public forums
- User-reported carrier information

**Limitations**:
- Unreliable, outdated, unverified

### VoIP Detection Techniques

**Google Voice Detection**:
```
"[phone number]" Google Voice
"[phone number]" GV number
```

**General VoIP Search**:
```
"[phone number]" VoIP OR "virtual number" OR "internet phone"
check if "[phone number]" is VoIP
```

**Provider-Specific Searches**:
```
"[phone number]" Skype
"[phone number]" Vonage
"[phone number]" RingCentral
```

**Prefix Analysis** (Manual):
- Certain area code + prefix combinations are known VoIP blocks
- Research: `"[area code]-[prefix]" VoIP block assignment`

### Line Type Indicators (in search results)

**Mobile/Wireless**:
- "mobile", "wireless", "cellular", "cell phone"
- Carrier names: Verizon Wireless, AT&T Mobility, T-Mobile

**Landline**:
- "landline", "fixed line", "wireline", "POTS"
- "fixed-line" (sometimes indicates VoIP, check context)

**VoIP**:
- "VoIP", "voice over IP", "internet phone"
- "virtual", "cloud", "hosted"
- Providers: Google Voice, Skype, RingCentral, Vonage

**Toll-Free**:
- Area codes: 800, 888, 877, 866, 855, 844, 833
- "toll-free service"

---

## Social Media & Professional Networks

### Platforms & Techniques

#### 1. LinkedIn
- **URL**: https://www.linkedin.com/
- **Privacy**: Public profiles may show contact info
- **Coverage**: Global, professional focus
- **Data Points**: Name, company, title, contact info (if public)
- **Reliability**: ⭐⭐⭐⭐ (High for business contacts)
- **Search Query**: `"[phone number]" site:linkedin.com`

**Best For**:
- Business phone numbers
- Professional contact verification
- Company identification

**Limitations**:
- Most phone numbers are private
- Requires LinkedIn membership for full access

#### 2. Facebook
- **URL**: https://www.facebook.com/
- **Privacy**: Most phone numbers hidden by privacy settings
- **Coverage**: Global, personal focus
- **Data Points**: Name, location (if phone number is public)
- **Reliability**: ⭐⭐ (Low - privacy protected)
- **Search Query**: `"[phone number]" site:facebook.com`

**Best For**:
- Public business pages
- Publicly posted contact information

**Limitations**:
- Phone number search largely blocked for privacy
- Most results are public posts mentioning the number

#### 3. Twitter (X)
- **URL**: https://twitter.com/
- **Privacy**: Rarely shows phone numbers
- **Coverage**: Global
- **Data Points**: Mentions in tweets (public posts)
- **Reliability**: ⭐⭐ (Low - sporadic)
- **Search Query**: `"[phone number]" site:twitter.com`

**Best For**:
- Public complaints about spam numbers
- Business contact information in tweets

**Limitations**:
- Phone numbers rarely in profiles
- Mostly spam reports, not attribution

#### 4. WhatsApp
- **Privacy**: Cannot search by phone number (ToS violation)
- **Coverage**: Global
- **OSINT Technique**: Can only verify if number is registered (requires manual check with app)
- **Reliability**: N/A (manual only, privacy-protected)
- **Search Query**: `"[phone number]" WhatsApp account`

**Best For**:
- Confirming number is active (if you can message it)
- Finding public references to WhatsApp number

**Limitations**:
- No API access for lookups
- Violates ToS to scrape
- Privacy settings prevent discovery

#### 5. Telegram
- **Privacy**: Username search possible, phone number search restricted
- **Coverage**: Global
- **OSINT Technique**: Can search username if known, phone lookup limited
- **Reliability**: ⭐⭐ (Low - privacy protected)
- **Search Query**: `"[phone number]" Telegram username`

**Best For**:
- Finding publicly shared Telegram contact info
- Username association (if known separately)

**Limitations**:
- Cannot directly lookup phone → user
- Privacy settings prevent most discovery
- Requires Telegram app for manual checks

### Social Media Search Techniques

**General Social Search**:
```
"[phone number]" social media profile account
```

**Multi-Platform Search**:
```
"[phone number]" site:linkedin.com OR site:facebook.com OR site:twitter.com
```

**Professional Contact Search**:
```
"[phone number]" contact business email professional
```

**Public Posts Mentioning Number**:
```
"[phone number]" "call me" OR "text me" OR "reach me"
```

**Business Social Pages**:
```
"[phone number]" business company "contact us" "call us"
```

---

## Public Records & Directories

### Business Directories

#### 1. Yellow Pages
- **URL**: https://www.yellowpages.com/
- **Type**: Business directory
- **Coverage**: US/Canada businesses
- **Data Points**: Business name, address, phone, website, hours
- **Reliability**: ⭐⭐⭐⭐ (High for businesses)
- **Search Query**: `"[phone number]" site:yellowpages.com`

**Best For**:
- Business identification
- Legitimate company verification
- Business contact validation

**Limitations**:
- Business-only (no personal numbers)
- Some listings outdated

#### 2. White Pages
- **URL**: https://www.whitepages.com/
- **Type**: People search and reverse phone lookup
- **Coverage**: US focus
- **Data Points**: Name, address, age, relatives (varies by privacy)
- **Reliability**: ⭐⭐⭐ (Moderate - privacy restrictions)
- **Search Query**: `"[phone number]" site:whitepages.com`

**Best For**:
- Personal phone number attribution
- Address association
- Background context

**Limitations**:
- Many results behind paywall
- Privacy opt-outs remove listings
- Data may be outdated

#### 3. Google Business Profile
- **URL**: Appears in Google search results
- **Type**: Business information from Google My Business
- **Coverage**: Global businesses
- **Data Points**: Business name, phone, address, hours, reviews
- **Reliability**: ⭐⭐⭐⭐ (High - business-verified)
- **Search Query**: `"[phone number]" business name address`

**Best For**:
- Legitimate business verification
- Operating hours and location
- Customer reviews

**Limitations**:
- Business-only
- Requires business to claim listing

### Search Techniques for Public Records

**Business Lookup**:
```
"[phone number]" business company name
"[phone number]" yellow pages listing
```

**Reverse Address**:
```
"[phone number]" address location
```

**Owner Search**:
```
"[phone number]" owner name registered
```

**Toll-Free Company**:
```
"1-800-[number]" company customer service
"[toll-free number]" corporate headquarters
```

---

## Search Engine Techniques

### Advanced Google Search Operators

#### Site-Specific Search
```
"[phone number]" site:example.com
```

#### Multiple Site Search
```
"[phone number]" site:siteA.com OR site:siteB.com OR site:siteC.com
```

#### Exclude Sites
```
"[phone number]" -site:spam.com
```

#### File Type Search
```
"[phone number]" filetype:pdf
```

#### Title Search
```
intitle:"[phone number]"
```

#### URL Search
```
inurl:"[phone number]"
```

#### Date Range
```
"[phone number]" after:2025-01-01 before:2025-12-31
```

#### Exact Phrase
```
"exactly this phrase including phone number"
```

### Search Query Strategies

#### Progressive Search (Narrow → Broad)

**Level 1: Exact Match**
```
"+1-555-123-4567"
"(555) 123-4567"
```

**Level 2: Number Only**
```
"5551234567"
"555-123-4567"
```

**Level 3: Number + Context**
```
"555-123-4567" spam OR scam OR complaint
```

**Level 4: Partial Number**
```
"555-1234" (last 7 digits for NANP)
"123-4567" (last 4 with local area)
```

#### Context-Based Searches

**Spam Investigation**:
```
"[number]" spam scam fraud phishing robocall
"[number]" "who called" OR "called me" complaint
"[number]" harass* OR threaten* OR suspicious
```

**Business Verification**:
```
"[number]" company business legitimate
"[number]" customer service OR support OR helpline
"[number]" official OR authorized OR verified
```

**Social/Personal**:
```
"[number]" contact OR "call me" OR "text me"
"[number]" profile OR account OR username
```

**Technical Investigation**:
```
"[number]" carrier OR operator OR provider
"[number]" VoIP OR virtual OR "Google Voice"
"[number]" registered OR assigned OR allocated
```

---

## Data Reliability Ratings

### Rating System

⭐⭐⭐⭐⭐ **Very High Reliability**
- Official/authoritative sources (NANPA, ITU)
- Standardized data with verification
- Regular updates from authoritative bodies
- Minimal risk of error

⭐⭐⭐⭐ **High Reliability**
- Large user base with active reporting (RoboKiller, YouMail)
- Business-verified information (Google Business, LinkedIn)
- Well-maintained databases
- Good update frequency

⭐⭐⭐ **Moderate Reliability**
- Smaller databases with less verification
- User-submitted without strong validation
- Moderate update frequency
- Some risk of outdated information

⭐⭐ **Low Reliability**
- Individual user reports without verification
- Infrequent updates
- Small sample size
- High risk of false positives/negatives

⭐ **Very Low Reliability**
- Unverified sources
- Anecdotal information
- No update mechanism
- High error rate

### Source Reliability by Category

**Area Code/Geographic Data**: ⭐⭐⭐⭐⭐
- Based on official NANP/ITU standards
- Highly accurate and reliable

**Spam/Scam Reports**: ⭐⭐⭐⭐
- Large databases are reliable (RoboKiller, YouMail)
- Subject to user bias (more complaints than positive)
- Newer numbers may have no reports

**Carrier Information (Free)**: ⭐⭐
- Often outdated due to number porting
- Approximate at best without paid APIs

**Social Media**: ⭐⭐
- Privacy settings limit discoverability
- What is found is usually accurate, but very limited

**VoIP Detection (Free)**: ⭐⭐
- Approximate without paid services
- Relies on indirect indicators

**Business Directories**: ⭐⭐⭐⭐
- High accuracy for listed businesses
- Missing/outdated entries possible

---

## Multi-Source Verification

### Best Practices

#### 1. Three-Source Rule
Always verify critical information from at least **three independent sources** before considering it reliable.

**Example**:
- Source 1: RoboKiller reports number as "IRS Scam"
- Source 2: YouMail categorizes as "Government Impersonation"
- Source 3: 800notes has user comments about IRS scam calls
- **Conclusion**: High confidence this is a scam number

#### 2. Source Diversity
Use sources from different categories:
- ✅ Spam database + public records + social media
- ❌ Three spam databases (all similar user bases)

#### 3. Date Verification
Check when information was last updated:
- Recent data (< 6 months) is more reliable
- Cross-reference old data with recent searches

#### 4. Volume Assessment
Consider the volume of reports:
- 100+ reports >> more reliable than 2-3 reports
- Single source with low volume = suspicious

#### 5. Consistency Check
Look for consistency across sources:
- Same company name across Yellow Pages, Google, LinkedIn = reliable
- Conflicting information = requires deeper investigation

### Red Flags (Indicating Unreliable Data)

🚩 **Single Source Only**: No corroboration
🚩 **Contradictory Reports**: Different sources give opposite information
🚩 **Very Old Data**: Last updated >2 years ago
🚩 **Low Report Volume**: Only 1-2 user reports
🚩 **Spelling Errors**: Indicates low-quality source
🚩 **Paywall for Key Info**: Data behind paywall can't be verified
🚩 **No Source Attribution**: Claims without sources

### Verification Workflow

```
Step 1: Collect data from multiple sources
        ↓
Step 2: Compare findings for consistency
        ↓
Step 3: Assess source reliability ratings
        ↓
Step 4: Check update dates and volume
        ↓
Step 5: Flag contradictions and gaps
        ↓
Step 6: Form conclusion with confidence level
        ↓
Step 7: Document all sources in report
```

### Confidence Levels

**High Confidence** (3+ reliable sources agree):
- Take action based on findings
- Include in formal reports

**Medium Confidence** (2 sources or mixed reliability):
- Use as supporting evidence
- Note uncertainty in reports
- Consider additional investigation

**Low Confidence** (1 source or contradictory):
- Treat as unverified lead
- Do not base decisions on this data
- Clearly mark as "unconfirmed" in reports

---

## Summary

### Quick Reference: Best Sources by Use Case

| Investigation Goal | Primary Sources | Reliability |
|-------------------|----------------|-------------|
| **Spam/Scam Check** | RoboKiller, YouMail, 800notes | ⭐⭐⭐⭐ |
| **Area Code Location** | AllAreaCodes.com, NANPA | ⭐⭐⭐⭐⭐ |
| **Business Verification** | Yellow Pages, Google Business | ⭐⭐⭐⭐ |
| **Carrier Lookup** | Web search (limited) | ⭐⭐ |
| **VoIP Detection** | Google Voice search, forums | ⭐⭐ |
| **Social Media** | LinkedIn, Facebook (limited) | ⭐⭐ |
| **International Numbers** | SpamCalls.net, Wikipedia | ⭐⭐⭐ |

### Key Takeaways

1. **Always use multiple sources** - Single-source data is unreliable
2. **Check reliability ratings** - Not all sources are equal
3. **Verify update dates** - Old data may be inaccurate
4. **Assess report volume** - More reports = higher confidence
5. **Document everything** - Cite all sources in reports
6. **Respect privacy** - Don't violate ToS or privacy laws
7. **Cross-verify** - Contradictions require deeper investigation
8. **Know limitations** - Free sources can't do everything

---

**Document Version**: 1.0
**Last Updated**: 2026-01-02
**Maintained By**: Paul Kincaid <paul@pksecure.io>
