#!/usr/bin/env python3
"""
Phone Number Validation and Parsing Tool

This script parses and validates phone numbers using the phonenumbers library,
extracting key components and providing detailed information about the number.

The phonenumbers library is a Python port of Google's libphonenumber library,
which provides robust international phone number parsing and validation.

Usage:
    python validate_phone.py "+1-555-123-4567"
    python validate_phone.py "(555) 123-4567" --region US
    python validate_phone.py "5551234567" --region US
    python validate_phone.py "+44 20 7183 8750" --region GB

Requirements:
    - Python 3.7+
    - phonenumbers library (install: pip install phonenumbers)

Author: Paul Kincaid <paul@pksecure.io>
License: Apache-2.0
"""

import sys
import argparse
import json
from typing import Dict, Any, Optional

try:
    import phonenumbers
    from phonenumbers import (
        geocoder,
        carrier,
        timezone,
        PhoneNumberType,
        NumberParseException
    )
except ImportError:
    print("Error: phonenumbers library not installed.", file=sys.stderr)
    print("Install it with: pip install phonenumbers", file=sys.stderr)
    sys.exit(1)


def parse_phone_number(number_string: str, region: Optional[str] = None) -> Optional[phonenumbers.PhoneNumber]:
    """
    Parse a phone number string into a PhoneNumber object.

    Args:
        number_string: Phone number as string (various formats accepted)
        region: ISO 3166-1 alpha-2 country code (e.g., 'US', 'GB', 'FR')
               Used as hint for parsing numbers without country code

    Returns:
        PhoneNumber object if parsing successful, None otherwise
    """
    try:
        parsed_number = phonenumbers.parse(number_string, region)
        return parsed_number
    except NumberParseException as e:
        print(f"Error parsing phone number: {e}", file=sys.stderr)
        return None


def get_number_type_name(number_type: PhoneNumberType) -> str:
    """Convert PhoneNumberType enum to human-readable string."""
    type_map = {
        PhoneNumberType.FIXED_LINE: "Landline (Fixed Line)",
        PhoneNumberType.MOBILE: "Mobile",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
        PhoneNumberType.TOLL_FREE: "Toll Free",
        PhoneNumberType.PREMIUM_RATE: "Premium Rate",
        PhoneNumberType.SHARED_COST: "Shared Cost",
        PhoneNumberType.VOIP: "VoIP",
        PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
        PhoneNumberType.PAGER: "Pager",
        PhoneNumberType.UAN: "UAN (Universal Access Number)",
        PhoneNumberType.VOICEMAIL: "Voicemail",
        PhoneNumberType.UNKNOWN: "Unknown"
    }
    return type_map.get(number_type, "Unknown")


def analyze_phone_number(parsed_number: phonenumbers.PhoneNumber) -> Dict[str, Any]:
    """
    Analyze a parsed phone number and extract detailed information.

    Args:
        parsed_number: PhoneNumber object from phonenumbers.parse()

    Returns:
        Dictionary containing detailed phone number information
    """
    # Validation
    is_valid = phonenumbers.is_valid_number(parsed_number)
    is_possible = phonenumbers.is_possible_number(parsed_number)

    # Number components
    country_code = parsed_number.country_code
    national_number = parsed_number.national_number

    # For NANP (North America), extract area code
    area_code = None
    if country_code == 1:  # NANP
        national_str = str(national_number)
        if len(national_str) == 10:
            area_code = national_str[:3]

    # Number type
    number_type = phonenumbers.number_type(parsed_number)
    number_type_name = get_number_type_name(number_type)

    # Geographic information
    geographic_description = geocoder.description_for_number(parsed_number, "en")

    # Carrier information (may not be available for all numbers)
    carrier_name = carrier.name_for_number(parsed_number, "en")

    # Time zones
    time_zones = timezone.time_zones_for_number(parsed_number)

    # Formatted output in various formats
    formats = {
        "e164": phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "national": phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL),
        "rfc3966": phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.RFC3966)
    }

    # Region code
    region_code = phonenumbers.region_code_for_number(parsed_number)

    return {
        "valid": is_valid,
        "possible": is_possible,
        "country_code": country_code,
        "national_number": national_number,
        "area_code": area_code,
        "region_code": region_code,
        "number_type": number_type_name,
        "geographic_location": geographic_description or "Unknown",
        "carrier": carrier_name or "Unknown",
        "time_zones": list(time_zones) if time_zones else [],
        "formatted": formats
    }


def format_output_text(analysis: Dict[str, Any]) -> str:
    """Format analysis results as human-readable text."""
    lines = [
        "=" * 60,
        "PHONE NUMBER ANALYSIS REPORT",
        "=" * 60,
        "",
        "VALIDATION:",
        f"  Valid Number:        {analysis['valid']}",
        f"  Possible Number:     {analysis['possible']}",
        "",
        "NUMBER COMPONENTS:",
        f"  Country Code:        +{analysis['country_code']}",
        f"  National Number:     {analysis['national_number']}",
        f"  Area Code:           {analysis['area_code'] or 'N/A'}",
        f"  Region Code:         {analysis['region_code']}",
        "",
        "NUMBER INFORMATION:",
        f"  Number Type:         {analysis['number_type']}",
        f"  Geographic Location: {analysis['geographic_location']}",
        f"  Carrier:             {analysis['carrier']}",
        f"  Time Zone(s):        {', '.join(analysis['time_zones']) or 'Unknown'}",
        "",
        "FORMATTED OUTPUT:",
        f"  E.164 Format:        {analysis['formatted']['e164']}",
        f"  International:       {analysis['formatted']['international']}",
        f"  National:            {analysis['formatted']['national']}",
        f"  RFC3966:             {analysis['formatted']['rfc3966']}",
        "",
        "=" * 60
    ]
    return "\n".join(lines)


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Parse and validate phone numbers with detailed analysis",
        epilog="Examples:\n"
               "  %(prog)s '+1-555-123-4567'\n"
               "  %(prog)s '(555) 123-4567' --region US\n"
               "  %(prog)s '+44 20 7183 8750'\n",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "phone_number",
        help="Phone number to analyze (various formats accepted)"
    )

    parser.add_argument(
        "-r", "--region",
        default=None,
        help="Region code for parsing (e.g., 'US', 'GB', 'FR'). "
             "Used as hint for numbers without country code."
    )

    parser.add_argument(
        "-f", "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )

    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress warnings and errors (only output results)"
    )

    args = parser.parse_args()

    # Parse the phone number
    parsed_number = parse_phone_number(args.phone_number, args.region)

    if parsed_number is None:
        if not args.quiet:
            print("\nFailed to parse phone number. Please check the format.", file=sys.stderr)
            print("Try specifying a region code with --region if the number lacks a country code.", file=sys.stderr)
        sys.exit(1)

    # Analyze the number
    analysis = analyze_phone_number(parsed_number)

    # Output results
    if args.format == "json":
        print(json.dumps(analysis, indent=2))
    else:
        print(format_output_text(analysis))

    # Exit with appropriate code
    sys.exit(0 if analysis['valid'] else 2)


if __name__ == "__main__":
    main()
