#!/usr/bin/env python3
"""
NANP Area Code Geolocation Lookup Tool

This script performs offline lookups of North American Numbering Plan (NANP)
area codes using a local CSV database. NANP covers the United States, Canada,
and several Caribbean nations.

The script can look up geographic information including state/province,
primary cities, coordinates, and time zones for any NANP area code.

Data Source:
    This script uses a CSV database of NANP area codes. A comprehensive
    database can be downloaded from:
    https://github.com/ravisorg/Area-Code-Geolocation-Database

Usage:
    python area_code_lookup.py 415
    python area_code_lookup.py 212 --format json
    python area_code_lookup.py 310 --csv ../assets/area_codes.csv

Requirements:
    - Python 3.7+
    - pandas library (install: pip install pandas)
    - CSV database file (area_codes.csv)

Author: Paul Kincaid <paul@pksecure.io>
License: Apache-2.0
"""

import sys
import argparse
import json
import os
from pathlib import Path
from typing import Dict, Any, Optional, List

try:
    import pandas as pd
except ImportError:
    print("Error: pandas library not installed.", file=sys.stderr)
    print("Install it with: pip install pandas", file=sys.stderr)
    sys.exit(1)


# Default path to CSV database (relative to this script)
DEFAULT_CSV_PATH = "../assets/area_codes.csv"


def find_csv_database(custom_path: Optional[str] = None) -> Optional[Path]:
    """
    Locate the area code CSV database file.

    Args:
        custom_path: Optional custom path to CSV file

    Returns:
        Path object to CSV file if found, None otherwise
    """
    if custom_path:
        path = Path(custom_path)
        if path.exists() and path.is_file():
            return path
        else:
            print(f"Error: Specified CSV file not found: {custom_path}", file=sys.stderr)
            return None

    # Try default path relative to this script
    script_dir = Path(__file__).parent
    default_path = script_dir / DEFAULT_CSV_PATH

    if default_path.exists() and default_path.is_file():
        return default_path

    print("Error: Area code database not found.", file=sys.stderr)
    print(f"Expected location: {default_path}", file=sys.stderr)
    print("\nTo obtain the database:", file=sys.stderr)
    print("1. Download from: https://github.com/ravisorg/Area-Code-Geolocation-Database", file=sys.stderr)
    print("2. Or create a CSV file with columns: area_code, state, city, latitude, longitude, timezone", file=sys.stderr)
    print("3. Place it at: ../assets/area_codes.csv (relative to this script)", file=sys.stderr)
    return None


def load_area_code_database(csv_path: Path) -> Optional[pd.DataFrame]:
    """
    Load the area code CSV database into a pandas DataFrame.

    Args:
        csv_path: Path to the CSV file

    Returns:
        DataFrame containing area code data, or None on error
    """
    try:
        df = pd.read_csv(csv_path)

        # Validate required columns
        required_columns = ['area_code']
        optional_columns = ['state', 'city', 'country', 'latitude', 'longitude', 'timezone']

        if 'area_code' not in df.columns:
            # Try alternate column names
            if 'npa' in df.columns:
                df.rename(columns={'npa': 'area_code'}, inplace=True)
            elif 'code' in df.columns:
                df.rename(columns={'code': 'area_code'}, inplace=True)
            else:
                print("Error: CSV file must have 'area_code', 'npa', or 'code' column", file=sys.stderr)
                return None

        # Ensure area_code is treated as string (to preserve leading zeros)
        df['area_code'] = df['area_code'].astype(str).str.zfill(3)

        return df

    except FileNotFoundError:
        print(f"Error: CSV file not found: {csv_path}", file=sys.stderr)
        return None
    except pd.errors.EmptyDataError:
        print(f"Error: CSV file is empty: {csv_path}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error loading CSV file: {e}", file=sys.stderr)
        return None


def lookup_area_code(area_code: str, df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Look up an area code in the database.

    Args:
        area_code: 3-digit area code (as string)
        df: DataFrame containing area code data

    Returns:
        List of dictionaries containing matching area code information
        (may be multiple entries for overlays or multiple cities)
    """
    # Normalize area code to 3 digits
    area_code = str(area_code).zfill(3)

    # Filter for matching area code
    matches = df[df['area_code'] == area_code]

    if matches.empty:
        return []

    # Convert matches to list of dictionaries
    results = []
    for _, row in matches.iterrows():
        result = {
            'area_code': row['area_code'],
        }

        # Add optional fields if they exist
        optional_fields = ['state', 'city', 'country', 'latitude', 'longitude', 'timezone', 'region']

        for field in optional_fields:
            if field in row.index and pd.notna(row[field]):
                result[field] = row[field]

        results.append(result)

    return results


def format_lookup_results_text(area_code: str, results: List[Dict[str, Any]]) -> str:
    """Format lookup results as human-readable text."""
    if not results:
        return f"No information found for area code {area_code}\n"

    lines = [
        "=" * 60,
        f"AREA CODE LOOKUP: {area_code}",
        "=" * 60,
        ""
    ]

    # If multiple results (overlay or multiple cities), number them
    for idx, result in enumerate(results, 1):
        if len(results) > 1:
            lines.append(f"LOCATION #{idx}:")
        else:
            lines.append("LOCATION:")

        lines.append(f"  Area Code:     {result['area_code']}")

        if 'country' in result:
            lines.append(f"  Country:       {result['country']}")

        if 'state' in result:
            lines.append(f"  State/Province: {result['state']}")

        if 'city' in result:
            lines.append(f"  City:          {result['city']}")

        if 'region' in result:
            lines.append(f"  Region:        {result['region']}")

        if 'timezone' in result:
            lines.append(f"  Time Zone:     {result['timezone']}")

        if 'latitude' in result and 'longitude' in result:
            lines.append(f"  Coordinates:   {result['latitude']}, {result['longitude']}")

        if idx < len(results):
            lines.append("")

    lines.extend([
        "",
        "=" * 60,
        ""
    ])

    if len(results) > 1:
        lines.insert(-3, f"\nNote: Found {len(results)} locations for this area code.")
        lines.insert(-3, "This may indicate an overlay area code or regional coverage.")

    return "\n".join(lines)


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Look up NANP area code geographic information",
        epilog="Examples:\n"
               "  %(prog)s 415\n"
               "  %(prog)s 212 --format json\n"
               "  %(prog)s 310 --csv /path/to/area_codes.csv\n",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "area_code",
        help="3-digit NANP area code to look up"
    )

    parser.add_argument(
        "--csv",
        default=None,
        help="Path to CSV database file (default: ../assets/area_codes.csv)"
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
        help="Suppress warnings (only output results)"
    )

    args = parser.parse_args()

    # Validate area code format
    if not args.area_code.isdigit() or len(args.area_code) > 3:
        if not args.quiet:
            print(f"Error: Invalid area code format: {args.area_code}", file=sys.stderr)
            print("Area code must be a 1-3 digit number.", file=sys.stderr)
        sys.exit(1)

    # Find and load the database
    csv_path = find_csv_database(args.csv)
    if csv_path is None:
        sys.exit(1)

    df = load_area_code_database(csv_path)
    if df is None:
        sys.exit(1)

    # Look up the area code
    results = lookup_area_code(args.area_code, df)

    # Output results
    if args.format == "json":
        output = {
            "area_code": args.area_code.zfill(3),
            "found": len(results) > 0,
            "count": len(results),
            "results": results
        }
        print(json.dumps(output, indent=2))
    else:
        print(format_lookup_results_text(args.area_code, results))

    # Exit with appropriate code
    sys.exit(0 if results else 2)


if __name__ == "__main__":
    main()
