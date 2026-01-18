---
name: phone-osint
description: Comprehensive phone number OSINT lookup including location, carrier type, spam reports, and messaging platform presence (WhatsApp, Telegram, Snapchat) using publicly available sources
license: Apache-2.0
compatibility: Designed for Claude Code. Requires internet access for web search functionality. Optional Python scripts require Python 3.7+ with phonenumbers library.
metadata:
  author: Paul Kincaid <paul@pksecure.io>
  version: "0.2"
  stage: dev
---

# Phone Number OSINT Lookup

This skill performs comprehensive Open Source Intelligence (OSINT) investigations on phone numbers using publicly available sources. It analyzes phone numbers to determine geographic location, carrier type, VoIP status, spam/scam reports, and potential social media presence.

## Supported Phone Number Formats

This skill handles multiple phone number formats:
- US/Canada: `(###) ###-####`, `###-###-####`, `+1-###-###-####`
- International: `+## ### ### ####` (country code + number)
- With or without country code prefix

## Instructions

When the user provides a phone number for investigation, follow these steps systematically:

### Step 1: Parse and Validate Phone Number

**Objective**: Normalize the phone number format and extract key components.

1. Identify the phone number format and extract components:
   - Remove formatting characters (parentheses, hyphens, spaces)
   - Identify country code (default to +1 for US/Canada if not specified)
   - Extract area code (first 3 digits after country code for NANP)
   - Extract prefix and line number

2. Perform initial validation using web search:
   - Search: `"phone number format [full number]"`
   - Search: `"[area code] area code location"` (for US/Canada numbers)
   - Search: `"+[country code] country"` (for international numbers)

3. Determine the phone number type:
   - **NANP** (North American Numbering Plan): US, Canada, Caribbean - starts with +1
   - **International**: Other country codes (+44, +33, +81, etc.)

**Output for this step**: Document the formatted number, country, area code/region code, and basic validation results.

### Step 2: Geographic Location Lookup

**Objective**: Determine the geographic location associated with the phone number's area code or country code.

**For US/Canada Numbers (NANP - Area Codes):**

1. Search for area code location information:
   - Search: `"[area code] area code location city state"`
   - Search: `"[area code] coverage area cities"`
   - Search: `"NPA [area code] geographic region"`
   - Search: `"[area code] time zone"`

2. Extract and document:
   - **Primary State/Province**: Where the area code is assigned
   - **Major Cities**: Primary cities covered by this area code
   - **Coverage Area**: Counties or regions served
   - **Time Zone**: Time zone(s) for the area code
   - **Area Code Type**: Geographic or overlay area code

**For International Numbers:**

1. Search for country and regional information:
   - Search: `"+[country code] country name"`
   - Search: `"[country code] [city code] location"` (if applicable)
   - Extract country name, major cities, and time zones

**Important Notes**:
- Area codes indicate the region where the number was originally assigned
- Mobile numbers and VoIP numbers can be used anywhere (not tied to physical location)
- Number portability means users can keep numbers when moving

**Output for this step**: Document the geographic location, coverage area, and time zone information.

### Step 3: Carrier and Line Type Detection

**Objective**: Determine if the number is a mobile phone, landline, VoIP service, or virtual number.

1. Search for carrier and line type information:
   - Search: `"[full phone number] carrier lookup"`
   - Search: `"[full phone number] VoIP landline mobile"`
   - Search: `"check if [phone number] is VoIP"`
   - Search: `"[area code]-[prefix] carrier database"`
   - Search: `"[phone number] line type"`

2. Look for indicators in search results:
   - **Mobile/Wireless**: "mobile", "wireless", "cellular", "cell phone"
   - **Landline**: "landline", "fixed line", "POTS" (Plain Old Telephone Service)
   - **VoIP**: "VoIP", "internet phone", "virtual", "Google Voice", "fixed VoIP"
   - **Toll-Free**: "toll-free", "800 service" (for 800, 888, 877, etc.)

3. Search for specific VoIP providers:
   - Search: `"[phone number] Google Voice"`
   - Search: `"[phone number] Skype number"`
   - Search: `"[phone number] virtual number provider"`

**Important Notes**:
- Without paid APIs, carrier detection is approximate and based on public databases
- Results may be outdated due to number porting
- VoIP numbers can be harder to identify accurately
- "Fixed line" results sometimes indicate VoIP services

**Output for this step**: Document the likely line type (mobile/landline/VoIP/unknown) and carrier name if found.

### Step 4: Spam/Scam Report Check

**Objective**: Check if the phone number has been reported for spam, scams, phishing, or fraudulent activity.

1. Search major spam reporting databases using site-specific searches:
   - Search: `"[phone number]" site:robokiller.com`
   - Search: `"[phone number]" site:youmail.com`
   - Search: `"[phone number]" site:spamcalls.net`
   - Search: `"[phone number]" site:800notes.com`
   - Search: `"[phone number]" site:whocallsme.com`
   - Search: `"[phone number]" site:callersmart.com`

2. Perform general spam reputation searches:
   - Search: `"[phone number]" spam scam reports`
   - Search: `"[phone number]" complaints reviews`
   - Search: `"[phone number]" who called me scam`
   - Search: `"[phone number]" robocall telemarketer`

3. For each source that has information, document:
   - **Source name and URL**: The website reporting the information
   - **Report count**: How many users reported this number (if available)
   - **Report type**: Spam, scam, telemarketer, legitimate business, etc.
   - **User comments**: Brief summary of what users reported
   - **Risk level**: Low/Medium/High based on volume and severity of reports

4. Assess overall spam risk:
   - **High**: Multiple reports across different sources, scam/fraud indicators
   - **Medium**: Some reports, telemarketing or nuisance calls
   - **Low**: Few or no reports, or reports indicate legitimate business
   - **Unknown**: No information found in databases

**Output for this step**: Document spam risk assessment, report count, and findings from each source with URLs.

### Step 5: Social Media Presence Check

**Objective**: Identify if the phone number is publicly associated with social media accounts.

**CRITICAL PRIVACY DISCLAIMER**: Most social media platforms (WhatsApp, Telegram, Snapchat) explicitly prohibit phone number lookups and protect user privacy. This step is LIMITED to publicly visible information only. Direct phone-to-user lookups violate Terms of Service and cannot be performed through web search. Manual verification with the platforms themselves may reveal account existence, but user details remain private.

#### A. General Social Media Search

1. Search for public mentions and associations:
   - Search: `"[phone number]" social media profile account`
   - Search: `"[phone number]" username handle`
   - Search: `"[phone number]" site:linkedin.com OR site:facebook.com OR site:twitter.com`

2. Search for business social media:
   - Search: `"[phone number]" business company contact`
   - Search: `"[phone number]" professional contact LinkedIn`

#### B. WhatsApp-Specific Search

**Privacy Note**: WhatsApp does NOT allow phone number searches. The only way to verify if a number is on WhatsApp is manual checking within the app (adding to contacts and seeing if WhatsApp profile appears).

1. Search for public references to WhatsApp number:
   - Search: `"[phone number]" WhatsApp`
   - Search: `"[phone number]" "WhatsApp me" OR "contact on WhatsApp"`
   - Search: `"[phone number]" site:wa.me` (WhatsApp click-to-chat links)

2. Check for WhatsApp Business listings:
   - Search: `"[phone number]" WhatsApp Business`

**What web search CAN find**:
- Public posts/websites mentioning "Contact us on WhatsApp: [number]"
- WhatsApp click-to-chat links (wa.me/[number]) posted publicly
- Business websites listing WhatsApp contact numbers

**What web search CANNOT find**:
- Whether the number has a WhatsApp account (requires manual app check)
- WhatsApp username or profile information
- WhatsApp profile photo or status

**Manual Verification Note**: To verify if a number is registered on WhatsApp, you would need to save it as a contact in your phone and check if a WhatsApp profile appears. This is the ONLY ToS-compliant method. Document finding as "Account existence can be manually verified via WhatsApp app" rather than claiming definitive registration status.

#### C. Telegram-Specific Search

**Privacy Note**: Telegram restricts phone number searches. Users can set privacy to hide their phone number from non-contacts.

1. Search for public Telegram references:
   - Search: `"[phone number]" Telegram`
   - Search: `"[phone number]" Telegram username @`
   - Search: `"[phone number]" t.me` (Telegram links)
   - Search: `"[phone number]" site:t.me`

2. Search for Telegram public channels/groups:
   - Search: `"[phone number]" Telegram channel OR group`

**What web search CAN find**:
- Public posts mentioning Telegram contact: "[number]"
- Telegram usernames publicly associated with the number
- Public Telegram channels/groups listing the number as contact
- t.me links posted on websites

**What web search CANNOT find**:
- Whether number has Telegram account (privacy protected)
- Private Telegram profile information
- Account creation date or activity

**Manual Verification Note**: To verify Telegram registration, you can attempt to start a chat with the number in Telegram app. If account exists and privacy allows, you'll see the profile. Document as "Telegram account existence can be verified manually via Telegram app" if web search is inconclusive.

#### D. Snapchat-Specific Search

**Privacy Note**: Snapchat does NOT support phone number searches. Users add friends by username, Snapcode, or phone contacts (mutual).

1. Search for public Snapchat references:
   - Search: `"[phone number]" Snapchat`
   - Search: `"[phone number]" Snapchat username`
   - Search: `"[phone number]" "add me on Snapchat" OR "Snapchat me"`
   - Search: `"[phone number]" snapchat.com`

2. Search for Snapchat usernames associated with number:
   - Search: `"[phone number]" snap username @`

**What web search CAN find**:
- Public social media posts where someone shared their phone number AND Snapchat username together
- Websites/profiles listing "Phone: [number], Snapchat: [username]"
- Public forums or posts mentioning both

**What web search CANNOT find**:
- Whether number is registered on Snapchat (no public lookup)
- Snapchat username directly from phone number
- Snapchat profile information

**Manual Verification Note**: Snapchat allows finding friends by syncing phone contacts. If you add the number to your phone contacts and sync with Snapchat, it will show if that number has a Snapchat account. Document as "Snapchat account existence can be verified manually via contact sync in Snapchat app."

#### E. Other Messaging Platforms

1. **Signal**:
   - Search: `"[phone number]" Signal messenger`
   - Note: Signal is privacy-focused; minimal public information available

2. **Instagram**:
   - Search: `"[phone number]" Instagram`
   - Search: `"[phone number]" site:instagram.com`

3. **TikTok**:
   - Search: `"[phone number]" TikTok`
   - Search: `"[phone number]" site:tiktok.com`

#### F. What CAN vs. CANNOT Be Done

**What CAN be found via web search**:
- ✅ Phone numbers publicly posted in social media profiles
- ✅ Business phone numbers on company pages
- ✅ Numbers shared in public posts, comments, or websites
- ✅ Professional contact information on LinkedIn
- ✅ Public posts saying "Contact me at [number] on [Platform]"
- ✅ Platform-specific links (wa.me, t.me) posted publicly

**What CANNOT be done (violates ToS/Privacy)**:
- ❌ Direct "phone number → username" lookup on WhatsApp/Telegram/Snapchat
- ❌ Accessing private profile information
- ❌ Using platform APIs without authorization
- ❌ Automated scraping of user data
- ❌ Circumventing privacy settings
- ❌ Reverse phone lookup within apps (unless manually verified)

#### G. Reporting Findings

**If web search finds public associations**:
- Document the platform, what was found, and cite the source URL
- Example: "Public Facebook post from 2024-01-15 mentions 'Contact me on WhatsApp: [number]' (URL: ...)"

**If web search finds nothing (common)**:
Report as:
```
**Web Search Results**: No publicly posted associations found for this number on WhatsApp, Telegram, or Snapchat through web search.

**Manual Verification Note**: Account existence on these platforms can only be verified through manual checking within each app:
- **WhatsApp**: Save number as contact, check if WhatsApp profile appears
- **Telegram**: Attempt to start chat with number in Telegram app
- **Snapchat**: Add number to contacts, sync with Snapchat to see if account exists

**Privacy Limitation**: Even if accounts exist on these platforms, user privacy settings typically prevent public discovery. Most users' phone numbers are hidden from search and only visible to contacts.
```

**Output for this step**:
- Document any publicly visible social media associations found via web search
- Include prominent disclaimer about privacy limitations and ToS restrictions
- Clearly distinguish between "web search found nothing" vs. "manual app verification needed"
- Note when manual verification is the only option (which is typical)
- Cite all sources with URLs
- DO NOT claim definitive "no account exists" unless verified manually

### Step 6: Additional OSINT Sources

**Objective**: Search additional public records and databases for information about the phone number.

1. Search public business directories:
   - Search: `"[phone number]" yellow pages business listing`
   - Search: `"[phone number]" white pages directory`
   - Search: `"[phone number]" business name company`

2. Search for owner/registration information:
   - Search: `"[phone number]" owner information`
   - Search: `"[phone number]" registered to`
   - Search: `"[phone number]" public records`

3. Search for historical/context information:
   - Search: `"[phone number]" "called me" OR "received call"`
   - Search: `"[phone number]" reviews complaints`

4. For toll-free numbers (800, 888, 877, 866, 855, 844, 833):
   - Search: `"[phone number]" toll free company name`
   - Search: `"1-800-[number] customer service"`

**Output for this step**: Document any additional information found from public records, business listings, or other OSINT sources.

### Step 7: Format and Present Output

**Objective**: Compile all gathered information into a clear, structured OSINT report.

Use the following template to present your findings:

```markdown
## Phone Number OSINT Report: [PHONE NUMBER]

**Number Analyzed**: [formatted number in international format]
**Report Generated**: [current date and time]
**Investigation Method**: Free OSINT sources (web search)

---

### Phone Number Details

| Property | Value |
|----------|-------|
| Original Format | [as provided by user] |
| International Format | [E.164 format: +X XXX XXX XXXX] |
| Country | [country name] |
| Country Code | [+X] |
| Area Code / Region Code | [XXX] |
| Line Type | [Mobile / Landline / VoIP / Unknown] |
| Carrier | [carrier name or "Unknown"] |

---

### Geographic Location

**Primary Location**: [City, State/Province, Country]

**Coverage Area**: [Additional cities or regions covered by this area code]

**Time Zone(s)**: [Time zone(s) for this area code]

**Location Notes**:
[Brief description of the geographic area. For mobile/VoIP numbers, note that the area code indicates where the number was assigned, not necessarily the current user location.]

---

### Spam/Scam Reports

**Spam Risk Assessment**: [Low / Medium / High / Unknown]

**Total Reports Found**: [number of reports across all sources]

**Detailed Findings**:

[For each source with information, format as follows:]

- **[Source Name]** ([URL])
  - Report Count: [number]
  - Report Types: [spam, scam, telemarketer, legitimate, etc.]
  - Summary: [brief summary of user reports]
  - Risk Indicators: [specific concerns mentioned]

[If no reports found:]
No spam or scam reports found in major spam databases. This suggests the number has not been widely reported for spam/scam activity, though absence of reports does not guarantee the number is legitimate.

---

### Social Media Presence

**Privacy Notice**: Social media platforms (especially WhatsApp, Telegram, and Snapchat) restrict phone number searches for user privacy. Results below are limited to publicly available information from web searches only and do not represent comprehensive account verification.

**Web Search Findings**:

[List any publicly visible associations found via web search:]

- **[Platform Name]**: [Description of what was found]
  - URL: [link to public profile/page]
  - Details: [additional context]

[If nothing found via web search:]

**Web Search Results**: No publicly posted associations found for this number on social media platforms through web search.

**Messaging Platforms (WhatsApp, Telegram, Snapchat)**:

**Manual Verification Note**: Account existence on WhatsApp, Telegram, and Snapchat cannot be determined through web search alone due to privacy protections. These platforms require manual verification:

- **WhatsApp**: To verify if registered, save number as contact and check if WhatsApp profile appears in the app
- **Telegram**: To verify if registered, attempt to start a chat with the number in Telegram app (if account exists and privacy allows, profile will appear)
- **Snapchat**: To verify if registered, add number to phone contacts and sync with Snapchat app to see if account appears

**Privacy Limitation**: Even if accounts exist on these platforms, user privacy settings typically prevent public discovery. Phone numbers are hidden from search and only visible to contacts. Web searches can only find publicly posted references (e.g., "Contact me on WhatsApp: [number]" in public posts).

**User Report Note**: [If you have been informed that accounts exist on these platforms, document it here:]
- Example: "Per user report, this number is registered on Snapchat and Telegram. Manual verification via respective apps is required to confirm account details, which will respect user privacy settings."

**Platforms Checked (Web Search)**: LinkedIn, Facebook, Twitter, Instagram, WhatsApp (public references), Telegram (public references), Snapchat (public references), business directories

---

### Additional Information

**Public Records & Business Listings**:

[Document any findings from business directories, white pages, yellow pages, or other public records]

- **[Source Type]**: [Information found]
  - URL: [link]

[If nothing found:]
No additional information found in public business directories or records.

---

### Key Findings Summary

[Provide 3-5 bullet points summarizing the most important findings from this investigation]

- [Key finding 1]
- [Key finding 2]
- [Key finding 3]

---

### Limitations & Disclaimers

**Data Accuracy**:
- Information is based on publicly available sources and may be incomplete or outdated
- Area codes indicate where numbers were originally assigned, not current user location
- Phone numbers can be reassigned, ported to different carriers, or spoofed
- Absence of spam reports does not guarantee a number is legitimate
- Free carrier data may be less accurate than paid API services

**Privacy & Legal Considerations**:
- This report is intended for legitimate investigative, security, or research purposes only
- Always respect privacy laws including GDPR, CCPA, and other applicable regulations
- Social media platform terms of service restrict automated phone number lookups
- Cross-verify information from multiple sources before taking action
- Phone number lookups should not be used for harassment, stalking, or unauthorized surveillance

**Technical Limitations**:
- VoIP and virtual number detection is approximate without paid APIs
- Real-time carrier information requires commercial lookup services
- Social media checks are severely limited due to privacy protections
- International number data may be less comprehensive than US/Canada
- Caller ID can be spoofed - displayed number ≠ actual caller

**Recommended Actions**:
- Cross-reference findings with multiple sources
- Consider context (time, frequency, content of calls/messages)
- For critical investigations, consider using paid verification services
- Report scam numbers to appropriate authorities (FTC, FCC, local law enforcement)

---

### Sources Consulted

[List ALL URLs consulted during this investigation, organized by category:]

**Area Code / Geographic Information**:
- [URL 1]
- [URL 2]

**Carrier / Line Type**:
- [URL 1]
- [URL 2]

**Spam/Scam Databases**:
- [URL 1]
- [URL 2]

**Social Media / Public Records**:
- [URL 1]
- [URL 2]

**Additional Sources**:
- [URL 1]
- [URL 2]

---

**Report End** - Generated by phone-osint skill for Claude Code
```

## Important Notes

### When to Use This Skill

- Investigating suspicious or unknown phone numbers
- Researching potential scam/spam callers
- Verifying business contact information
- Security incident response involving phone-based attacks (vishing, smishing)
- Background research for fraud investigations
- Validating phone numbers before callbacks

### When NOT to Use This Skill

- For unauthorized surveillance or stalking
- To violate someone's privacy rights
- In violation of platform terms of service
- For harassment or malicious purposes
- When you lack proper authorization for the investigation

### Data Source Reliability

**Most Reliable**:
- Area code geographic data (standardized NANP database)
- Country code information (ITU standards)
- Spam databases with many user reports

**Moderately Reliable**:
- Carrier information from web search (may be outdated)
- Business directory listings (depends on update frequency)
- User-reported spam data (subjective)

**Least Reliable**:
- VoIP detection without paid APIs (approximate)
- Social media associations (privacy-limited)
- Caller ID information (easily spoofed)

### Error Handling

**If phone number format is invalid**:
- Attempt to parse with common patterns
- Ask user to clarify the number format
- Document the issue in the report

**If no information is found**:
- Document that searches were performed but yielded no results
- Note which sources were checked
- Explain that absence of information is common for new/private numbers

**If results are contradictory**:
- Document all findings, noting the contradictions
- Cite sources for each piece of information
- Recommend cross-verification and caution in conclusions

**If access to sources is blocked**:
- Try alternative search queries
- Document which sources were inaccessible
- Note the limitation in the report

## Optional: Python Scripts

The `scripts/` directory contains optional Python tools that can enhance phone number analysis:

- **validate_phone.py**: Parse and validate phone numbers using the `phonenumbers` library
- **area_code_lookup.py**: Offline NANP area code database lookup

These scripts are optional. The skill's primary functionality uses web search and does not require running these scripts. However, they can provide faster, offline validation if Python and required libraries are installed.

To use the scripts:
```bash
cd scripts/
pip install -r requirements.txt
python validate_phone.py "+1-555-123-4567"
python area_code_lookup.py 555
```

See the README.md and individual script documentation for details.

## References

For additional information, see the reference files in the `references/` directory:

- **OSINT_SOURCES.md**: Detailed list of OSINT sources and search techniques
- **PRIVACY.md**: Privacy laws, ethical guidelines, and legal considerations
- **LIMITATIONS.md**: Known limitations and accuracy considerations
- **API_GUIDE.md**: Optional paid APIs for enhanced lookups (reference only)

These references provide deeper context and are loaded on-demand when needed for complex investigations.
