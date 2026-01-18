# Optional Paid APIs for Enhanced Phone Number OSINT

This reference document provides information about paid API services that can enhance phone number investigations beyond what free sources provide. This is **reference material only** - the phone-osint skill uses free sources by default.

**Note**: This guide is for informational purposes. The author has no financial relationship with any mentioned vendors.

**Last Updated**: 2026-01-02

---

## Table of Contents

1. [Overview](#overview)
2. [Carrier Lookup Services](#carrier-lookup-services)
3. [Number Validation Services](#number-validation-services)
4. [Reputation & Spam Detection](#reputation--spam-detection)
5. [Caller Name (CNAM) Lookup](#caller-name-cnam-lookup)
6. [Advanced Telecom APIs](#advanced-telecom-apis)
7. [Cost Comparison](#cost-comparison)
8. [API Integration Guidelines](#api-integration-guidelines)
9. [When to Consider Paid APIs](#when-to-consider-paid-apis)

---

## Overview

### What Paid APIs Provide

Paid services offer capabilities not available through free sources:

✅ **Real-Time Carrier Lookup** - Current carrier, not original assignment
✅ **Line Type Detection** - Accurate mobile/landline/VoIP classification
✅ **Number Validation** - Live verification if number is in service
✅ **HLR/LRN Queries** - Home Location Register, Local Routing Number data
✅ **Caller Name (CNAM)** - Official caller ID database
✅ **Porting History** - When number was ported between carriers
✅ **Reputation Scores** - AI-powered fraud risk assessment
✅ **International Coverage** - Better data for non-NANP numbers

### Pricing Models

**Pay-Per-Lookup**:
- Charges per API call (e.g., $0.01-$0.10 per lookup)
- Good for low-volume, occasional use
- No monthly commitment

**Subscription**:
- Monthly fee for included lookups (e.g., $50/month for 10,000 lookups)
- Better for regular/high-volume use
- Often includes multiple API types

**Credits**:
- Pre-purchase credits, use as needed
- Credits expire after set period (e.g., 12 months)
- Flexibility without monthly commitment

### Typical Costs (2026)

| Service Type | Cost Per Lookup | Typical Subscription |
|--------------|-----------------|---------------------|
| Basic Validation | $0.001 - $0.01 | $10-50/month |
| Carrier Lookup | $0.01 - $0.05 | $50-200/month |
| HLR Query | $0.02 - $0.10 | $100-500/month |
| CNAM Lookup | $0.01 - $0.02 | $50-150/month |
| Reputation Score | $0.05 - $0.20 | $200-1000/month |

---

## Carrier Lookup Services

### 1. Twilio Lookup API

**Provider**: Twilio Inc.
**Website**: https://www.twilio.com/lookup

**Capabilities**:
- Carrier identification (name, type, mobile country/network codes)
- Line type detection (mobile, landline, VoIP)
- Number formatting and validation
- Caller name (CNAM) - US/Canada
- Reputation/spam risk assessment

**Coverage**:
- Global (200+ countries)
- Best for NANP (US/Canada)

**Pricing** (2026 estimates):
- Basic validation: ~$0.005/lookup
- Carrier lookup: ~$0.005/lookup
- Line type: ~$0.01/lookup
- CNAM: ~$0.01/lookup

**API Example**:
```python
from twilio.rest import Client

client = Client(account_sid, auth_token)
number = client.lookups.v2.phone_numbers('+15551234567').fetch(
    fields='carrier,line_type_intelligence'
)

print(f"Carrier: {number.carrier['name']}")
print(f"Line Type: {number.line_type_intelligence['type']}")
```

**Pros**:
- Excellent documentation
- Reliable infrastructure
- Wide coverage
- Multiple features in one API

**Cons**:
- Can be expensive for high volume
- Requires Twilio account setup

---

### 2. Telnyx Number Lookup

**Provider**: Telnyx LLC
**Website**: https://telnyx.com/products/number-lookup

**Capabilities**:
- Real-time carrier lookup
- Porting history
- Line type classification
- Number validity

**Coverage**:
- Global coverage
- Strong international support

**Pricing**:
- ~$0.004/lookup (carrier)
- Volume discounts available

**API Example**:
```python
import telnyx

telnyx.api_key = "YOUR_API_KEY"

number = telnyx.NumberLookup.retrieve('+15551234567')
print(f"Carrier: {number.carrier.name}")
print(f"Type: {number.number_type}")
```

**Pros**:
- Competitive pricing
- Good international coverage
- Fast response times

**Cons**:
- Less well-known than Twilio
- Fewer integrations

---

### 3. NumVerify API

**Provider**: APILayer (Apilayer Data Products GmbH)
**Website**: https://numverify.com/

**Capabilities**:
- Phone number validation
- Carrier detection
- Line type identification
- Location data
- International format conversion

**Coverage**:
- Global (200+ countries)
- Good for international numbers

**Pricing**:
- Free tier: 250 lookups/month
- Basic: $12/month (5,000 lookups)
- Professional: $50/month (50,000 lookups)
- Enterprise: Custom pricing

**API Example**:
```python
import requests

API_KEY = 'your_api_key'
phone = '14155551234'

response = requests.get(f'http://apilayer.net/api/validate?access_key={API_KEY}&number={phone}')
data = response.json()

print(f"Valid: {data['valid']}")
print(f"Carrier: {data['carrier']}")
print(f"Line Type: {data['line_type']}")
```

**Pros**:
- Free tier for testing
- Affordable paid tiers
- Simple API
- Good international support

**Cons**:
- Less detailed than Twilio/Telnyx
- Rate limits on free tier

---

## Number Validation Services

### 1. AbstractAPI Phone Validation

**Provider**: Abstract API
**Website**: https://www.abstractapi.com/phone-validation-api

**Capabilities**:
- Phone number validation and formatting
- Carrier and line type detection
- International support
- Timezone information

**Pricing**:
- Free: 250 lookups/month
- Starter: $10/month (1,000 lookups)
- Production: $50/month (10,000 lookups)

**Pros**:
- Generous free tier
- Simple to use
- Good documentation

**Cons**:
- Limited advanced features

---

### 2. Veriphone API

**Provider**: Veriphone
**Website**: https://veriphone.io/

**Capabilities**:
- Real-time phone verification
- International number validation
- Carrier detection
- Fraud risk scoring

**Pricing**:
- Free: 1,000 lookups (one-time)
- Pay-as-you-go: $0.01/lookup

**Pros**:
- True pay-as-you-go (no subscription)
- International focus

**Cons**:
- Limited carrier details

---

## Reputation & Spam Detection

### 1. IPQS (IPQualityScore) Phone Validation

**Provider**: IPQualityScore LLC
**Website**: https://www.ipqualityscore.com/phone-number-validator

**Capabilities**:
- **Fraud risk scoring** (0-100 score)
- VOIP/prepaid/disposable detection
- Carrier and line type
- Active/disconnected status
- SMS reachability
- Do Not Call registry check
- Recent activity detection

**Coverage**: Global

**Pricing**:
- Free tier: 5,000 lookups/month
- Paid: $0.0045 - $0.05/lookup (volume-based)

**API Example**:
```python
import requests

API_KEY = 'your_key'
phone = '15551234567'

response = requests.get(f'https://ipqualityscore.com/api/json/phone/{API_KEY}/{phone}')
data = response.json()

print(f"Fraud Score: {data['fraud_score']}")
print(f"VOIP: {data['VOIP']}")
print(f"Active: {data['active']}")
```

**Pros**:
- Excellent fraud detection
- Comprehensive data
- Free tier available

**Cons**:
- Can be expensive for high volumes

---

### 2. Telesign Score API

**Provider**: Telesign
**Website**: https://www.telesign.com/products/phone-id

**Capabilities**:
- PhoneID Score (fraud risk)
- Number type and carrier
- Phone number intelligence
- Registration and usage patterns

**Coverage**: Global

**Pricing**: Custom (enterprise focus)

**Pros**:
- Advanced fraud detection
- Enterprise-grade

**Cons**:
- Expensive
- Requires sales contact

---

## Caller Name (CNAM) Lookup

### 1. OpenCNAM

**Provider**: OpenCNAM (Telo USA)
**Website**: https://www.opencnam.com/

**Capabilities**:
- Caller ID name lookup
- Standard and premium CNAM databases
- Bulk lookup support

**Coverage**: US/Canada NANP

**Pricing**:
- Hobbyist: Free tier (60 calls/hour)
- Professional: $0.004/lookup (standard)
- Premium: $0.01/lookup (extended databases)

**API Example**:
```python
import requests

phone = '+15551234567'
response = requests.get(f'https://api.opencnam.com/v3/phone/{phone}?format=json')
data = response.json()

print(f"Name: {data['name']}")
```

**Pros**:
- Affordable
- Free tier for testing
- CNAM-specific (authoritative data)

**Cons**:
- NANP only
- Rate limits on free tier

---

### 2. Twilio Caller Name Lookup

**Provider**: Twilio (covered above)

**Capabilities**:
- CNAM via Lookup API
- Integrated with other Twilio services

**Pricing**: ~$0.01/lookup

**Pros**:
- Part of comprehensive platform
- Reliable

**Cons**:
- More expensive than OpenCNAM

---

## Advanced Telecom APIs

### 1. HLR Lookup (Home Location Register)

**What It Does**:
- Queries telecom SS7 network for number status
- Confirms if number is active/in-service
- Current network location (country/network)
- Roaming status

**Providers**:
- **HLR Lookup**: https://www.hlrlookup.com/ (~$0.02-0.05/query)
- **Telnyx HLR**: https://telnyx.com/ (integrated with carrier lookup)
- **Twilio**: Available via Lookup API

**Use Cases**:
- SMS delivery verification
- Confirming number is active before calling
- Detecting ported/disconnected numbers

**Pricing**: $0.02-$0.10/query

**Caution**: HLR queries can be expensive; use selectively

---

### 2. LRN (Local Routing Number) Lookup

**What It Does**:
- Identifies current carrier for ported numbers
- Returns routing number for interconnection
- Determines wireless vs. wireline

**Providers**:
- **Neustar**: Enterprise-focused
- **iconectiv**: Official NANP registry
- **Bandwidth**: https://www.bandwidth.com/

**Use Cases**:
- Accurate carrier identification post-porting
- Telecom routing
- Regulatory compliance (TCPA)

**Pricing**: $0.01-$0.03/lookup

**Coverage**: NANP (US/Canada)

---

## Cost Comparison

### Monthly Subscription Comparison (1,000 lookups/month)

| Provider | Basic Validation | Carrier Lookup | Advanced (HLR/CNAM) | Total (est.) |
|----------|------------------|----------------|---------------------|--------------|
| **NumVerify** | Included | Included | N/A | $12/month |
| **AbstractAPI** | Included | Included | N/A | $10/month |
| **Twilio** | $5 | $5 | +$10 | $20/month |
| **IPQS** | Included | Included | Included | $15/month |
| **Telnyx** | $4 | $4 | +$20 | $28/month |

### Pay-Per-Lookup Comparison (No Subscription)

| Provider | Per Lookup Cost | Minimum Purchase |
|----------|-----------------|------------------|
| **Veriphone** | $0.01 | $0 (PAYG) |
| **IPQS** | $0.0045-0.05 | Credits system |
| **Twilio** | $0.005-0.01 | Add credits |
| **HLR Lookup** | $0.02-0.05 | Credit bundles |

### Best Value Recommendations

**Low Volume (< 500/month)**:
- Free tiers: NumVerify, AbstractAPI, IPQS
- Pay-per-use: Veriphone

**Medium Volume (500-5,000/month)**:
- NumVerify Basic: $12/month
- AbstractAPI Starter: $10/month
- IPQS: $15/month (best fraud detection)

**High Volume (5,000+/month)**:
- Negotiate custom pricing
- Consider multiple providers for redundancy
- Twilio/Telnyx for enterprise needs

---

## API Integration Guidelines

### Security Best Practices

**API Key Management**:
- Never hardcode API keys in scripts
- Use environment variables: `os.environ.get('API_KEY')`
- Use secrets management (AWS Secrets Manager, Azure Key Vault)
- Rotate keys regularly
- Use separate keys for dev/staging/production

**Example**:
```python
import os
from dotenv import load_dotenv

load_dotenv()  # Load from .env file
API_KEY = os.environ.get('NUMVERIFY_API_KEY')

if not API_KEY:
    raise ValueError("API key not found in environment")
```

### Error Handling

**Robust Error Handling**:
```python
import requests
from requests.exceptions import RequestException, Timeout

def lookup_carrier(phone, api_key):
    try:
        response = requests.get(
            f'https://api.example.com/lookup?phone={phone}&key={api_key}',
            timeout=10  # 10 second timeout
        )
        response.raise_for_status()  # Raise exception for 4xx/5xx
        return response.json()

    except Timeout:
        print("API request timed out")
        return None

    except RequestException as e:
        print(f"API request failed: {e}")
        return None

    except ValueError:
        print("Invalid JSON response")
        return None
```

### Rate Limiting

**Respect Rate Limits**:
```python
import time
from functools import wraps

def rate_limit(max_calls_per_second=5):
    min_interval = 1.0 / max_calls_per_second
    last_called = [0.0]

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_called[0]
            left_to_wait = min_interval - elapsed
            if left_to_wait > 0:
                time.sleep(left_to_wait)

            ret = func(*args, **kwargs)
            last_called[0] = time.time()
            return ret
        return wrapper
    return decorator

@rate_limit(max_calls_per_second=2)
def api_lookup(phone):
    # API call here
    pass
```

### Caching Results

**Avoid Redundant Lookups**:
```python
from functools import lru_cache
import hashlib

@lru_cache(maxsize=1000)
def cached_lookup(phone_hash):
    # Perform actual API lookup
    return api_call(phone_hash)

def lookup_with_cache(phone, api_key):
    # Hash phone to use as cache key
    phone_hash = hashlib.md5(phone.encode()).hexdigest()
    return cached_lookup(phone_hash)
```

### Retry Logic

**Graceful Retry on Failures**:
```python
import time
from requests.exceptions import RequestException

def api_call_with_retry(phone, api_key, max_retries=3):
    for attempt in range(max_retries):
        try:
            response = requests.get(api_url, params={'phone': phone, 'key': api_key})
            response.raise_for_status()
            return response.json()

        except RequestException as e:
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt  # Exponential backoff
                print(f"Retry {attempt+1}/{max_retries} after {wait_time}s...")
                time.sleep(wait_time)
            else:
                print(f"All retries failed: {e}")
                return None
```

---

## When to Consider Paid APIs

### Use Cases for Paid APIs

✅ **High-Stakes Investigations**:
- Fraud cases involving significant financial loss
- Law enforcement investigations requiring court-admissible evidence
- Litigation support where accuracy is critical

✅ **High-Volume Operations**:
- Processing hundreds/thousands of numbers daily
- Automated fraud detection systems
- Call center operations requiring real-time validation

✅ **SMS/Voice Campaign Validation**:
- Verifying numbers before bulk SMS campaigns (TCPA compliance)
- Reducing failed call attempts
- Ensuring SMS deliverability

✅ **When Free Sources Are Insufficient**:
- Need real-time carrier information (not historical)
- Require VoIP detection with high accuracy
- Need to verify if number is currently active
- International numbers with poor free coverage

✅ **Professional Services**:
- Providing OSINT as a service to clients
- Security consulting with SLA requirements
- Automated monitoring/alerting systems

### When to Stick with Free Sources

✅ **Ad-Hoc Investigations**:
- One-off number lookups
- Personal curiosity/safety checks
- Low-stakes research

✅ **Budget Constraints**:
- Individual investigators
- Non-profit research
- Educational purposes

✅ **Sufficient Free Data**:
- Spam/scam checking (free databases are good)
- Area code location (free sources are authoritative)
- Basic validation (free libraries like phonenumbers)

---

## Integration Example: Hybrid Approach

Combining free and paid sources for optimal cost/benefit:

```python
import phonenumbers
import requests
import os

def phone_lookup(number_string, use_paid_api=False):
    """
    Hybrid phone number lookup combining free and paid sources.

    Args:
        number_string: Phone number to investigate
        use_paid_api: If True, use paid API for enhanced data
    """
    results = {}

    # Step 1: Free validation using phonenumbers library
    try:
        parsed = phonenumbers.parse(number_string, None)
        results['valid'] = phonenumbers.is_valid_number(parsed)
        results['country_code'] = parsed.country_code
        results['national_number'] = parsed.national_number
        results['number_type'] = phonenumbers.number_type(parsed)
        results['location'] = phonenumbers.geocoder.description_for_number(parsed, 'en')
    except:
        results['valid'] = False
        return results

    # Step 2: Free spam database check (web search simulation)
    # (In practice, use WebSearch or scraping within ToS)
    results['spam_risk'] = check_spam_databases(number_string)

    # Step 3: Optional paid API for carrier/advanced data
    if use_paid_api and results['valid']:
        api_key = os.environ.get('CARRIER_API_KEY')
        if api_key:
            try:
                response = requests.get(
                    f'https://api.carrier-lookup.com/v1/lookup',
                    params={'phone': number_string, 'key': api_key},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    results['carrier_current'] = data.get('carrier')
                    results['line_type_accurate'] = data.get('line_type')
                    results['active_status'] = data.get('active')
            except:
                pass  # Fallback to free data

    return results

def check_spam_databases(phone):
    """
    Simulate checking free spam databases.
    In practice, use web search or API calls within rate limits.
    """
    # Placeholder - implement web search logic
    return "Unknown"

# Usage
result = phone_lookup("+1-415-555-1212", use_paid_api=False)  # Free only
result_enhanced = phone_lookup("+1-415-555-1212", use_paid_api=True)  # With paid API
```

---

## Summary

### Key Takeaways

1. **Free sources are sufficient for most investigations**
   - Spam checks, area codes, basic validation

2. **Paid APIs provide precision and real-time data**
   - Current carrier, active status, advanced fraud detection

3. **Choose based on use case and budget**
   - Ad-hoc: Free
   - High-volume or high-stakes: Paid

4. **Security and compliance matter**
   - Protect API keys
   - Handle errors gracefully
   - Respect rate limits

5. **Hybrid approach often optimal**
   - Use free sources first
   - Add paid APIs only when necessary

### Recommendation for Phone-OSINT Skill

The current implementation uses **free sources only** by design:
- Accessible to all users
- No API keys required
- Sufficient for most investigative purposes

**When to upgrade**: If users frequently need carrier accuracy or real-time validation, consider adding optional paid API integration as an enhancement.

---

**Document Version**: 1.0
**Last Updated**: 2026-01-02
**Maintained By**: Paul Kincaid <paul@pksecure.io>

**Disclaimer**: Pricing and features subject to change. Verify current offerings with providers before purchasing.
