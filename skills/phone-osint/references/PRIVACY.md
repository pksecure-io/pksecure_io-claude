# Privacy & Legal Considerations for Phone Number OSINT

This document provides guidance on privacy laws, ethical guidelines, and legal considerations when conducting phone number OSINT investigations.

**⚠️ IMPORTANT**: This document provides general information only and is not legal advice. Always consult with qualified legal counsel for specific situations.

**Last Updated**: 2026-01-02

---

## Table of Contents

1. [Privacy Laws & Regulations](#privacy-laws--regulations)
2. [Platform Terms of Service](#platform-terms-of-service)
3. [Ethical Guidelines](#ethical-guidelines)
4. [Authorized Use Cases](#authorized-use-cases)
5. [Prohibited Activities](#prohibited-activities)
6. [Data Handling Best Practices](#data-handling-best-practices)
7. [International Considerations](#international-considerations)
8. [When to Seek Legal Counsel](#when-to-seek-legal-counsel)

---

## Privacy Laws & Regulations

### United States

#### 1. Telephone Consumer Protection Act (TCPA)
- **Enacted**: 1991, amended multiple times
- **Scope**: Regulates telemarketing and use of automatic telephone equipment
- **Relevant Provisions**:
  - Restrictions on unsolicited calls/texts
  - Do Not Call Registry requirements
  - Prior express consent for marketing calls
- **OSINT Impact**: Reverse lookups are generally legal, but using numbers for marketing without consent violates TCPA
- **Penalties**: Up to $1,500 per violation

**Key Takeaway**: Looking up numbers for investigative purposes is legal; using them for unauthorized calls/texts is not.

#### 2. Privacy Act of 1974
- **Scope**: Regulates federal government's collection and use of personal information
- **Relevant Provisions**:
  - Limits on federal agency data collection
  - Individual rights to access their own records
  - Restrictions on disclosure
- **OSINT Impact**: Using publicly available government records is legal; accessing restricted federal databases is not
- **Penalties**: Criminal and civil penalties for violations

**Key Takeaway**: Public records are fair game; restricted government databases require authorization.

#### 3. California Consumer Privacy Act (CCPA)
- **Enacted**: 2018, effective 2020
- **Scope**: California residents' personal information
- **Relevant Provisions**:
  - Right to know what data is collected
  - Right to delete personal information
  - Right to opt-out of sale of personal information
  - Notice requirements for data collection
- **OSINT Impact**: Collecting publicly available data is allowed; selling or improperly using PI may violate CCPA
- **Penalties**: Up to $7,500 per violation

**Key Takeaway**: Public OSINT is legal, but commercial use of personal data may require CCPA compliance.

#### 4. Fair Credit Reporting Act (FCRA)
- **Scope**: Consumer reports used for credit, employment, insurance decisions
- **Relevant Provisions**:
  - Permissible purposes for obtaining consumer reports
  - Accuracy and dispute requirements
  - User responsibilities
- **OSINT Impact**: Phone lookups for background checks may be regulated if used for employment/credit decisions
- **Penalties**: Civil and criminal penalties

**Key Takeaway**: Using phone OSINT for employment/credit decisions requires FCRA compliance or falls under permissible purposes.

#### 5. Computer Fraud and Abuse Act (CFAA)
- **Scope**: Unauthorized access to computer systems
- **Relevant Provisions**:
  - Prohibits unauthorized access to protected computers
  - Exceeding authorized access
  - Applies to systems affecting interstate commerce
- **OSINT Impact**: Accessing public websites is legal; hacking, scraping in violation of ToS, or unauthorized database access violates CFAA
- **Penalties**: Criminal penalties, up to 20 years for aggravated cases

**Key Takeaway**: Stay within authorized access; don't hack or violate access controls.

### European Union

#### General Data Protection Regulation (GDPR)
- **Effective**: May 25, 2018
- **Scope**: EU residents' personal data, regardless of where processing occurs
- **Relevant Provisions**:
  - Lawful basis for processing (consent, legitimate interest, etc.)
  - Data minimization principle
  - Right to be forgotten
  - Data protection impact assessments
  - Significant fines for violations

**Personal Data**: Phone numbers are "personal data" under GDPR

**Lawful Bases for Phone Number OSINT**:
1. **Legitimate Interest** (Art. 6(1)(f)):
   - Fraud prevention and security investigations
   - Must balance against data subject rights
   - Requires legitimate interest assessment (LIA)

2. **Legal Obligation** (Art. 6(1)(c)):
   - Compliance with legal requirements
   - Law enforcement cooperation

3. **Public Interest** (Art. 6(1)(e)):
   - Official investigations
   - Public safety

**OSINT Impact**:
- Publicly available data can be processed, but must respect data minimization
- Data subjects have right to object
- Must document lawful basis
- International transfers require safeguards

**Penalties**: Up to €20 million or 4% of global revenue, whichever is higher

**Key Takeaway**: GDPR applies if you process EU residents' phone numbers. Ensure lawful basis and respect data subject rights.

### Canada

#### Personal Information Protection and Electronic Documents Act (PIPEDA)
- **Scope**: Private sector organizations' collection, use, and disclosure of personal information
- **Relevant Provisions**:
  - Consent requirements for collection
  - Purpose specification
  - Limiting collection, use, disclosure
  - Individual access rights

**OSINT Impact**:
- Publicly available information has fewer restrictions
- Business contact information may be exempt
- Commercial use requires consent or legitimate purpose

**Penalties**: Fines up to CAD $100,000

**Key Takeaway**: Public OSINT is generally permitted; commercial use of personal data requires care.

### Other Jurisdictions

**Australia** - Privacy Act 1988 (Australian Privacy Principles)
**Brazil** - Lei Geral de Proteção de Dados (LGPD)
**India** - Personal Data Protection Bill (pending)
**China** - Personal Information Protection Law (PIPL)
**Japan** - Act on the Protection of Personal Information (APPI)

Each has unique requirements. **Consult local legal counsel for specific jurisdictions**.

---

## Platform Terms of Service

### Social Media Platforms

#### WhatsApp Terms of Service
**Prohibited Activities**:
- ❌ Automated phone number lookups via unofficial APIs
- ❌ Scraping user data
- ❌ Using service for surveillance

**Permitted Activities**:
- ✅ Manual checks (e.g., seeing if contact is on WhatsApp)
- ✅ Public references to WhatsApp numbers (from other sources)

**Enforcement**: Account suspension/termination for violations

#### Telegram Terms of Service
**Prohibited Activities**:
- ❌ Automated scraping of user data
- ❌ Bulk contact discovery
- ❌ Using bots to harvest phone numbers

**Permitted Activities**:
- ✅ Manual username searches
- ✅ Public channel information

**Enforcement**: Account ban, legal action for egregious violations

#### LinkedIn User Agreement
**Prohibited Activities**:
- ❌ Scraping member data without consent
- ❌ Automated profile collection
- ❌ Using data for purposes outside LinkedIn

**Permitted Activities**:
- ✅ Viewing publicly visible profiles
- ✅ Searching for business contacts (within platform)

**Enforcement**: Account restriction, legal action, monetary damages

#### Facebook Terms of Service
**Prohibited Activities**:
- ❌ Collecting user data using automated means
- ❌ Phone number searches via Graph API without authorization
- ❌ Violating privacy settings

**Permitted Activities**:
- ✅ Viewing public business pages
- ✅ Information shared publicly by users

**Enforcement**: Account termination, legal action

#### Twitter (X) Terms of Service
**Prohibited Activities**:
- ❌ Excessive automated scraping
- ❌ Violating rate limits
- ❌ Misusing API access

**Permitted Activities**:
- ✅ Public tweet searches (within rate limits)
- ✅ Viewing public profiles

**Enforcement**: Account suspension, API access revocation

### Search Engines

#### Google Terms of Service
**Prohibited Activities**:
- ❌ Automated queries (excessive scraping)
- ❌ Circumventing rate limits
- ❌ Using for unauthorized commercial purposes

**Permitted Activities**:
- ✅ Manual searches
- ✅ Reasonable automated searches (e.g., research within limits)

**Enforcement**: IP blocking, CAPTCHA, service termination

### Compliance Recommendations

1. **Read and respect ToS** for all platforms you use
2. **Avoid automated scraping** unless explicitly permitted
3. **Stay within rate limits** to avoid triggering anti-bot measures
4. **Use official APIs** when available and authorized
5. **Respect robots.txt** files
6. **Don't circumvent access controls** or anti-scraping measures
7. **Stop if blocked** - blocking indicates you're violating ToS

---

## Ethical Guidelines

### Professional Ethics for OSINT

#### 1. Legitimate Purpose
**Do**:
- ✅ Conduct investigations for lawful security, fraud prevention, or research purposes
- ✅ Clearly define investigation scope and objectives
- ✅ Ensure purpose aligns with legal and ethical standards

**Don't**:
- ❌ Use OSINT for harassment, stalking, or intimidation
- ❌ Conduct investigations without legitimate justification
- ❌ Exceed scope of authorization

#### 2. Proportionality
**Do**:
- ✅ Collect only information necessary for the investigation
- ✅ Use least intrusive methods appropriate for the purpose
- ✅ Balance investigation needs against privacy rights

**Don't**:
- ❌ Collect excessive or unrelated information
- ❌ Use invasive techniques when less intrusive methods suffice
- ❌ Retain data longer than necessary

#### 3. Transparency
**Do**:
- ✅ Document methodology and sources
- ✅ Be honest about capabilities and limitations
- ✅ Disclose conflicts of interest

**Don't**:
- ❌ Misrepresent findings or sources
- ❌ Hide methodology to obscure questionable practices
- ❌ Present speculation as fact

#### 4. Respect for Privacy
**Do**:
- ✅ Respect privacy settings and access controls
- ✅ Consider impact on data subjects
- ✅ Protect sensitive information discovered during investigations

**Don't**:
- ❌ Circumvent privacy settings
- ❌ Publish sensitive personal information unnecessarily
- ❌ Disregard reasonable expectations of privacy

#### 5. Accuracy and Verification
**Do**:
- ✅ Verify information from multiple sources
- ✅ Clearly distinguish between confirmed facts and assumptions
- ✅ Correct errors when discovered

**Don't**:
- ❌ Present unverified information as fact
- ❌ Rely on single sources for critical findings
- ❌ Ignore contradictory evidence

#### 6. Responsible Disclosure
**Do**:
- ✅ Share findings only with authorized parties
- ✅ Protect identities of innocent parties
- ✅ Follow responsible disclosure for security issues

**Don't**:
- ❌ Publicly dox individuals
- ❌ Share findings irresponsibly
- ❌ Disclose sensitive information to unauthorized parties

### Ethical Decision Framework

When faced with ethical dilemmas, ask:

1. **Is it legal?** - Does it violate any laws or regulations?
2. **Is it authorized?** - Do I have permission to conduct this investigation?
3. **Is it proportional?** - Are my methods appropriate for the purpose?
4. **Is it accurate?** - Have I verified the information?
5. **Is it necessary?** - Do I need this specific information?
6. **Is it respectful?** - Does it respect privacy and dignity?
7. **Is it transparent?** - Can I clearly document and justify my actions?

If the answer to any question is "no" or "uncertain," **stop and reconsider**.

---

## Authorized Use Cases

### Legitimate Investigative Purposes

✅ **Security Incident Response**
- Investigating vishing (voice phishing) attacks
- Analyzing smishing (SMS phishing) campaigns
- Tracing threatening or harassing calls
- Fraud investigation and prevention

✅ **Cybersecurity Research**
- Analyzing threat actor infrastructure
- Studying scam/spam patterns
- Telecommunications security research
- Attribution in security incidents

✅ **Due Diligence**
- Verifying business contact information
- Validating vendor/partner credentials
- Customer authentication (with proper authorization)
- Employment verification (FCRA-compliant)

✅ **Law Enforcement (Authorized)**
- Criminal investigations (with proper authorization)
- Missing persons cases
- Fraud/scam investigations
- Evidence gathering for court cases

✅ **Journalism & Research**
- Investigative journalism (public interest)
- Academic research (ethics board approved)
- Public safety reporting
- Consumer protection investigations

✅ **Personal Safety**
- Identifying unknown callers for personal safety
- Blocking spam/scam numbers
- Verifying contacts before callback
- Domestic violence/stalking self-protection (consult law enforcement)

### Required Authorizations

**Corporate Investigations**: Require authorization from:
- Legal department
- Security/compliance team
- Management (for employee investigations)

**Law Enforcement**: Require:
- Proper legal process (warrants, subpoenas, court orders)
- Departmental authorization
- Jurisdictional authority

**Third-Party Investigations**: Require:
- Signed agreement with client
- Clear scope of work
- Legal basis for investigation

---

## Prohibited Activities

### Illegal Uses

❌ **Stalking or Harassment**
- Using phone OSINT to stalk, intimidate, or harass individuals
- Doxing (publicly revealing private information)
- Cyberbullying or threatening behavior

**Legal Consequences**: Criminal stalking/harassment charges, restraining orders, civil lawsuits

❌ **Identity Theft or Fraud**
- Using information for fraudulent purposes
- Pretexting (pretending to be someone else)
- Unauthorized account access

**Legal Consequences**: Federal criminal charges (identity theft, wire fraud), imprisonment, fines

❌ **Unauthorized Surveillance**
- Monitoring individuals without lawful authority
- Using information to track someone's movements
- Invasive data collection

**Legal Consequences**: Wiretapping charges, privacy violation lawsuits, regulatory penalties

❌ **Violation of Access Controls**
- Hacking into systems to obtain phone data
- Circumventing security measures
- Exceeding authorized access

**Legal Consequences**: CFAA violations, criminal hacking charges, civil damages

❌ **Discriminatory Purposes**
- Using phone data for illegal discrimination (housing, employment, credit)
- Profiling based on protected characteristics
- Violating fair lending or fair housing laws

**Legal Consequences**: Civil rights violations, FCRA violations, regulatory enforcement

❌ **Unauthorized Marketing**
- Using phone numbers for unsolicited marketing without consent
- Violating Do Not Call Registry
- TCPA violations

**Legal Consequences**: FTC enforcement, TCPA lawsuits ($500-$1,500 per call)

### Unethical Uses

Even if not explicitly illegal, avoid:

- ❌ Invading reasonable expectations of privacy
- ❌ Using information to embarrass or shame individuals
- ❌ Conducting investigations without legitimate purpose
- ❌ Sharing sensitive information irresponsibly
- ❌ Exceeding scope of authorization
- ❌ Misrepresenting findings or capabilities

---

## Data Handling Best Practices

### Data Minimization

**Collect Only What's Necessary**:
- Define investigation scope clearly
- Collect only relevant information
- Avoid "just in case" data hoarding

**Example**:
- ✅ Collect: Phone number, spam reports, carrier type (for spam investigation)
- ❌ Avoid: Social media profiles, personal addresses, family information (if not relevant)

### Secure Storage

**Protect Collected Data**:
- Use encrypted storage for investigation files
- Implement access controls (need-to-know basis)
- Use secure communication channels
- Avoid cloud storage without proper security (check provider compliance)

**Retention Limits**:
- Delete data when investigation is complete
- Follow organizational retention policies
- Don't retain data indefinitely without justification

### Disclosure Controls

**Need-to-Know Principle**:
- Share findings only with authorized parties
- Use secure channels for sensitive communications
- Redact unnecessary personal information in reports

**Protect Innocent Parties**:
- Minimize disclosure of information about uninvolved individuals
- Redact names/details of bystanders in reports
- Avoid collateral damage to privacy

### Audit Trail

**Document Everything**:
- Record all sources consulted
- Log search queries and methods
- Note date/time of information collection
- Maintain chain of custody for evidence

**Why**: Supports accountability, legal defensibility, quality assurance

### Data Subject Rights

**Be Prepared to Handle Requests**:
- Right to access (provide copy of data held)
- Right to rectification (correct inaccurate data)
- Right to erasure (delete data when no longer needed)
- Right to object (honor opt-out requests)

**GDPR/CCPA Compliance**: Have processes in place to handle these requests

---

## International Considerations

### Cross-Border Data Transfers

**GDPR Requirements**:
- Transfers to non-EU countries require adequacy decision or safeguards
- Standard Contractual Clauses (SCCs) for transfers
- Binding Corporate Rules (BCRs) for intra-company transfers

**Other Jurisdictions**:
- China PIPL: Requires security assessment for cross-border transfers
- Russia: Data localization requirements
- India: Proposed localization requirements

**Best Practice**: Understand data residency requirements before conducting international OSINT

### Cultural Considerations

**Privacy Expectations Vary**:
- EU: Strong privacy culture, GDPR compliance critical
- US: Less restrictive, but state laws (CCPA) increasing
- Asia: Varies widely (Japan high privacy, China restrictive)

**Approach**:
- Research local privacy norms
- Respect cultural expectations even if not legally required
- When in doubt, err on side of privacy

### Local Laws

**Always check**:
- Local data protection laws
- Telecommunications regulations
- Surveillance/investigative authorities requirements

**Example**: Some countries require law enforcement involvement for certain types of investigations

---

## When to Seek Legal Counsel

### Mandatory Legal Consultation

Seek legal advice **before** proceeding if:

1. **Law Enforcement Involvement**
   - Investigation may lead to criminal charges
   - Coordination with law enforcement required
   - Subpoena or warrant needed

2. **Cross-Border Investigations**
   - Subject or data located in foreign jurisdiction
   - International data transfers
   - Compliance with foreign laws uncertain

3. **Employment/Credit Decisions**
   - Using phone OSINT for hiring decisions
   - Credit or lending decisions
   - FCRA compliance required

4. **Litigation Support**
   - Evidence for civil lawsuit
   - Criminal defense investigations
   - Expert witness testimony

5. **Regulatory Uncertainty**
   - Unclear if activity complies with GDPR/CCPA
   - Novel use case without precedent
   - Potential for significant penalties

### Recommended Legal Consultation

Consider consulting legal counsel for:

- Large-scale investigations affecting many individuals
- Sensitive cases (executives, public figures, minors)
- Potential for public disclosure of findings
- Client requests that seem questionable
- Situations where you feel uncomfortable proceeding

### Questions to Ask Legal Counsel

1. Is this investigation legally permitted in our jurisdiction?
2. Do we need authorization or legal process (warrant, subpoena)?
3. Are there privacy laws that restrict our methods?
4. What data handling requirements apply (retention, disclosure)?
5. What are the legal risks if we proceed?
6. Should we involve law enforcement?
7. How should we document this investigation for legal defensibility?

---

## Summary Checklist

Before conducting phone number OSINT, verify:

**Legal Compliance**:
- [ ] I have a legitimate purpose for this investigation
- [ ] I am authorized to conduct this investigation
- [ ] My methods comply with applicable privacy laws (GDPR, CCPA, etc.)
- [ ] I am not violating platform terms of service
- [ ] I am not exceeding authorized access (CFAA compliance)

**Ethical Considerations**:
- [ ] My investigation is proportional to the purpose
- [ ] I am collecting only necessary information
- [ ] I respect privacy expectations and settings
- [ ] I will verify findings before reporting
- [ ] I will protect sensitive information appropriately

**Data Handling**:
- [ ] I have secure storage for collected data
- [ ] I have a data retention and deletion plan
- [ ] I will share findings only with authorized parties
- [ ] I will document all sources and methods

**Risk Assessment**:
- [ ] I understand the legal risks
- [ ] I have consulted legal counsel if necessary
- [ ] I am prepared to handle data subject rights requests
- [ ] I have considered international law implications

If you cannot check all applicable boxes, **stop and reassess** before proceeding.

---

## Resources

### Legal Resources

**United States**:
- [FTC TCPA Compliance Guide](https://www.ftc.gov/tips-advice/business-center/guidance/complying-telemarketing-sales-rule)
- [FCC Do Not Call Registry](https://www.fcc.gov/consumers/guides/stop-unwanted-calls-texts-and-faxes)
- [FCRA Summary](https://www.ftc.gov/enforcement/statutes/fair-credit-reporting-act)

**European Union**:
- [GDPR Official Text](https://gdpr-info.eu/)
- [European Data Protection Board](https://edpb.europa.eu/)

**International**:
- [IAPP (International Association of Privacy Professionals)](https://iapp.org/)
- [Privacy Laws by Country](https://www.dlapiperdataprotection.com/)

### Ethics Resources

- [OSINT Framework Code of Ethics](https://osintframework.com/)
- [IntelTechniques Ethics](https://inteltechniques.com/ethics.html)
- [Bellingcat Ethics Policy](https://www.bellingcat.com/about/ethics/)

---

**Disclaimer**: This document provides general information and is not legal advice. Laws vary by jurisdiction and change over time. Always consult with qualified legal counsel for specific situations.

**Document Version**: 1.0
**Last Updated**: 2026-01-02
**Maintained By**: Paul Kincaid <paul@pksecure.io>
