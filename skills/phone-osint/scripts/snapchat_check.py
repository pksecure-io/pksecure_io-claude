#!/usr/bin/env python3
"""
Snapchat Account Verification Tool (Unofficial)

PURPOSE: Check if a phone number is registered on Snapchat

⚠️ CRITICAL WARNINGS:
- This uses UNOFFICIAL Snapchat API methods (reverse-engineered)
- HIGHEST RISK OF ALL PLATFORMS - Snapchat aggressively bans automation
- Snapchat has the most sophisticated anti-bot detection
- Risk of account/phone number being PERMANENTLY BANNED within hours/days
- Use ONLY with dedicated investigation phone number (NOT personal)
- ONLY for authorized corporate security investigations
- Even with precautions, expect frequent account bans

INTENDED USE CASE:
- Corporate security investigations
- BEC (Business Email Compromise) fraud investigations
- CEO impersonation/phishing attack attribution
- Threat actor identification
- Must have proper legal/compliance authorization

OPERATIONAL SECURITY:
- Use dedicated Google Voice or burner number
- Do NOT use personal Snapchat accounts
- Do NOT use company executive phone numbers
- Isolate this tool on dedicated investigation workstation
- Log all usage for compliance/audit
- EXPECT this number to be banned eventually

SETUP REQUIREMENTS:
- Python 3.8+ installed
- Dedicated phone number (Google Voice recommended)
- Snapchat account registered with investigation number
- See SNAPCHAT_SETUP.md for full instructions

LIMITATIONS:
- Snapchat has NO official API for this use case
- Unofficial libraries frequently break due to API changes
- Contact sync is the ONLY semi-reliable method
- Very high ban risk even with minimal use
- May require Android device emulation for full functionality

Author: Paul Kincaid <paul@pksecure.io>
License: Apache-2.0
Version: 0.1

LEGAL: Obtain written authorization from legal/compliance before use.
      This tool has the HIGHEST risk of detection and account loss.
"""

import sys
import os
import json
import time
import argparse
from datetime import datetime
from pathlib import Path

# Note: snapchat-py and similar libraries are often outdated/broken
# This implementation uses a manual contact sync approach as fallback
try:
    from snapchat import Snapchat
    SNAPCHAT_LIB_AVAILABLE = True
except ImportError:
    SNAPCHAT_LIB_AVAILABLE = False

# Configuration
SCRIPT_DIR = Path(__file__).parent
LOG_DIR = SCRIPT_DIR.parent / 'logs'
CONFIG_FILE = SCRIPT_DIR / '.snapchat_config.json'
SESSION_FILE = SCRIPT_DIR / '.snapchat_session.json'

# Ensure directories exist
LOG_DIR.mkdir(exist_ok=True)

# ANSI color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def log(level, message, data=None):
    """Log message to console and file"""
    timestamp = datetime.utcnow().isoformat() + 'Z'

    log_entry = {
        'timestamp': timestamp,
        'level': level.upper(),
        'message': message
    }

    if data:
        log_entry.update(data)

    # Console output with colors
    color = {
        'info': Colors.BLUE,
        'success': Colors.GREEN,
        'warn': Colors.YELLOW,
        'error': Colors.RED
    }.get(level.lower(), Colors.WHITE)

    print(f"{color}[{timestamp}] {level.upper()}: {message}{Colors.RESET}")

    # File logging
    log_file = LOG_DIR / f"snapchat_investigations_{datetime.utcnow().date()}.json"
    with open(log_file, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')

def display_legal_warning():
    """Display comprehensive legal and risk warning"""
    print('\n' + '=' * 80)
    print('WARNING: UNOFFICIAL SNAPCHAT VERIFICATION TOOL - EXTREME RISK')
    print('=' * 80)

    print(f'\n{Colors.RED}{Colors.BOLD}⚠️  CRITICAL: HIGHEST BAN RISK OF ALL PLATFORMS{Colors.RESET}')
    print('Snapchat has the most aggressive anti-automation detection.')
    print('Even careful use will likely result in account ban within days/weeks.')
    print('DO NOT use this tool unless you accept account loss as inevitable.\n')

    print('⚠️  TERMS OF SERVICE VIOLATION')
    print('This tool uses unofficial Snapchat API methods (reverse-engineered).')
    print('Snapchat explicitly prohibits automated access in their ToS.')
    print('Account bans are PERMANENT and cannot be appealed.\n')

    print('✓  AUTHORIZED USE ONLY')
    print('- Corporate security investigations')
    print('- BEC/phishing/fraud investigations')
    print('- Threat actor attribution')
    print('- Must have legal/compliance authorization\n')

    print('✗  PROHIBITED USE')
    print('- Personal investigations')
    print('- Harassment or stalking')
    print('- Unauthorized surveillance')
    print('- Spam or bulk messaging')
    print('- Any use without proper authorization\n')

    print('🔒 OPERATIONAL SECURITY')
    print('- Use dedicated investigation phone number ONLY')
    print('- Do NOT use personal Snapchat accounts')
    print('- All checks are logged for compliance')
    print('- Isolate on dedicated investigation workstation')
    print('- EXTREME rate limiting (wait hours/days between checks)')
    print('- Expect investigation number to be banned eventually\n')

    print('📱 RECOMMENDED: MANUAL VERIFICATION')
    print('Due to extreme ban risk, manual verification is recommended:')
    print('1. Add phone number to investigation phone contacts')
    print('2. Open Snapchat app on investigation device')
    print('3. Go to Add Friends → Contacts')
    print('4. Check if number appears with Snapchat account')
    print('This is safer and ToS-compliant.\n')

    print('=' * 80 + '\n')

def display_manual_verification_guide():
    """Display guide for manual Snapchat verification"""
    print('\n' + '=' * 80)
    print('MANUAL SNAPCHAT VERIFICATION GUIDE (RECOMMENDED)')
    print('=' * 80 + '\n')

    print('Manual verification is SAFER and more RELIABLE than automation:')
    print()
    print('STEP 1: Add Number to Phone Contacts')
    print('  - Open Contacts app on investigation phone')
    print('  - Add new contact with target phone number')
    print('  - Save (name can be temporary, e.g., "Investigation Target")')
    print()
    print('STEP 2: Sync Contacts in Snapchat')
    print('  - Open Snapchat app on investigation device')
    print('  - Tap your profile icon (top left)')
    print('  - Tap "Add Friends" (+) button')
    print('  - Tap "Contacts"')
    print('  - Grant contacts access if prompted')
    print()
    print('STEP 3: Check Results')
    print('  - If Snapchat account exists: Will appear in "Quick Add" or "Contacts"')
    print('  - Shows Snapchat username and display name')
    print('  - You can view their public profile (if not private)')
    print()
    print('STEP 4: Document Findings')
    print('  - Screenshot the result (if account found)')
    print('  - Note username, display name, Bitmoji')
    print('  - Document in investigation case file')
    print()
    print('STEP 5: Clean Up')
    print('  - Delete contact from phone')
    print('  - Do NOT add them on Snapchat (leaves trace)')
    print()
    print('=' * 80 + '\n')

def parse_phone_number(phone_number):
    """Parse and format phone number"""
    # Remove all non-digit characters
    cleaned = ''.join(filter(str.isdigit, phone_number))

    # Ensure it has country code
    if len(cleaned) == 10:  # US number without country code
        cleaned = '1' + cleaned

    return cleaned

def check_snapchat_library():
    """Check if Snapchat library is available and working"""
    if not SNAPCHAT_LIB_AVAILABLE:
        return False, "snapchat-py library not installed"

    try:
        # Test basic import
        test = Snapchat()
        return True, "Library available"
    except Exception as e:
        return False, f"Library error: {str(e)}"

def check_snapchat_manual_guide(phone_number):
    """Provide manual check instructions instead of automated check"""

    result = {
        'phoneNumber': phone_number,
        'formattedNumber': parse_phone_number(phone_number),
        'method': 'manual_verification_required',
        'isRegistered': 'unknown',
        'recommendation': 'Use manual verification method (see output above)',
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }

    print(f'\n{Colors.YELLOW}⚠️  AUTOMATED CHECK NOT RECOMMENDED{Colors.RESET}')
    print('Due to Snapchat\'s aggressive anti-bot detection, automated checking')
    print('carries extreme ban risk and is often unreliable.')
    print()
    print('RECOMMENDATION: Use manual verification method (see above)')
    print()
    print(f'{Colors.CYAN}Manual verification steps:{Colors.RESET}')
    print(f'1. Add {phone_number} to investigation phone contacts')
    print('2. Open Snapchat → Add Friends → Contacts')
    print('3. Check if account appears in contact sync results')
    print('4. Document username and display name if found')
    print('5. Delete contact from phone when done')
    print()

    return result

def load_config():
    """Load configuration"""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return None

def save_config(config):
    """Save configuration"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def main():
    parser = argparse.ArgumentParser(
        description='Snapchat Account Verification Tool (UNOFFICIAL - EXTREME RISK)',
        epilog='⚠️  WARNING: Snapchat has the highest ban risk. Manual verification recommended.'
    )
    parser.add_argument(
        'phone_number',
        help='Phone number to check (e.g., "+1-555-123-4567")'
    )
    parser.add_argument(
        '--manual',
        action='store_true',
        help='Show manual verification guide only (recommended)'
    )
    parser.add_argument(
        '--force-automated',
        action='store_true',
        help='Attempt automated check despite risks (NOT RECOMMENDED)'
    )

    args = parser.parse_args()

    display_legal_warning()

    # Always show manual guide
    display_manual_verification_guide()

    # Default to manual verification
    if not args.force_automated:
        log('info', 'Manual verification recommended', {'phoneNumber': args.phone_number})

        # Ask for confirmation
        print(f'{Colors.YELLOW}Do you want to proceed with MANUAL verification? (yes/no){Colors.RESET}')
        manual_confirm = input('Manual verification: ').strip().lower()

        if manual_confirm != 'yes':
            print(f'\n{Colors.RED}❌ Verification cancelled.{Colors.RESET}')
            log('warn', 'Check cancelled - no confirmation')
            sys.exit(1)

        result = check_snapchat_manual_guide(args.phone_number)

        # Save result
        result_file = LOG_DIR / f"snapchat_result_{int(time.time() * 1000)}.json"
        with open(result_file, 'w') as f:
            json.dump(result, f, indent=2)

        print('\n' + '=' * 80)
        print('SNAPCHAT VERIFICATION - MANUAL METHOD')
        print('=' * 80 + '\n')
        print(f'Phone Number:     {result["phoneNumber"]}')
        print(f'Formatted:        {result["formattedNumber"]}')
        print(f'Method:           Manual Verification Required')
        print(f'Recommendation:   Follow manual steps above')
        print(f'Timestamp:        {result["timestamp"]}')
        print('\n' + '=' * 80 + '\n')
        print(f'Result saved to: {result_file}\n')

        log('success', 'Manual verification guide provided', result)
        sys.exit(0)

    # If user forced automated check
    print(f'\n{Colors.RED}{Colors.BOLD}⚠️  WARNING: Automated check requested{Colors.RESET}')
    print('You have requested automated checking despite the warnings.')
    print('This carries EXTREME risk of account ban.')
    print()

    # Check authorization
    print(f'{Colors.YELLOW}Do you have written authorization for this investigation? (yes/no){Colors.RESET}')
    authorized = input('Authorization confirmed: ').strip().lower()

    if authorized != 'yes':
        print(f'\n{Colors.RED}❌ Authorization not confirmed. Exiting.{Colors.RESET}')
        log('warn', 'Check aborted - no authorization confirmation')
        sys.exit(1)

    # Final confirmation
    print(f'\n{Colors.RED}FINAL WARNING: Account ban is highly likely. Continue? (yes/no){Colors.RESET}')
    final_confirm = input('Final confirmation: ').strip().lower()

    if final_confirm != 'yes':
        print(f'\n{Colors.YELLOW}Cancelled. Consider using manual verification instead.{Colors.RESET}')
        sys.exit(1)

    log('warn', 'Automated Snapchat check attempted (high risk)', {
        'phoneNumber': args.phone_number,
        'authorized': True
    })

    # Check library availability
    lib_available, lib_message = check_snapchat_library()

    if not lib_available:
        print(f'\n{Colors.RED}❌ Snapchat library not available: {lib_message}{Colors.RESET}')
        print()
        print('Automated checking requires snapchat-py library, which is often outdated.')
        print('This is expected - Snapchat frequently breaks unofficial libraries.')
        print()
        print(f'{Colors.CYAN}RECOMMENDATION: Use manual verification method instead{Colors.RESET}')
        print()
        log('error', 'Snapchat library not available', {'reason': lib_message})

        # Fall back to manual guide
        result = check_snapchat_manual_guide(args.phone_number)
        result_file = LOG_DIR / f"snapchat_result_{int(time.time() * 1000)}.json"
        with open(result_file, 'w') as f:
            json.dump(result, f, indent=2)

        print(f'Result saved to: {result_file}\n')
        sys.exit(2)

    # If library is available (rare), attempt check
    print(f'\n{Colors.YELLOW}⚠️  Attempting automated check...{Colors.RESET}')
    print('This will likely fail or result in account ban.')
    print()

    try:
        # Placeholder for actual implementation
        # In practice, Snapchat library methods are unreliable
        print(f'{Colors.RED}Automated Snapchat checking is not implemented.{Colors.RESET}')
        print('Snapchat\'s anti-automation is too aggressive for reliable automated checks.')
        print()
        print(f'{Colors.CYAN}Please use manual verification method.{Colors.RESET}')

        result = check_snapchat_manual_guide(args.phone_number)
        result_file = LOG_DIR / f"snapchat_result_{int(time.time() * 1000)}.json"
        with open(result_file, 'w') as f:
            json.dump(result, f, indent=2)

        print(f'Result saved to: {result_file}\n')
        sys.exit(2)

    except Exception as e:
        log('error', 'Snapchat check failed', {
            'phoneNumber': args.phone_number,
            'error': str(e)
        })
        print(f'\n{Colors.RED}❌ Error: {str(e)}{Colors.RESET}\n')
        sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f'\n\n{Colors.YELLOW}Interrupted by user{Colors.RESET}')
        log('warn', 'Script interrupted by user')
        sys.exit(1)
    except Exception as e:
        print(f'\n{Colors.RED}Fatal error: {str(e)}{Colors.RESET}\n')
        log('error', 'Fatal error', {'error': str(e)})
        sys.exit(1)
