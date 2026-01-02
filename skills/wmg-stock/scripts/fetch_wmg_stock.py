#!/usr/bin/env python3
"""
WMG Stock Data Fetcher with Competitor Analysis

This script fetches Warner Music Group (WMG) stock data and compares it with
competitors (Universal Music Group and Sony) over a 90-day period.

Requirements:
    - Python 3.7+
    - yfinance
    - pandas

Install dependencies:
    pip install -r requirements.txt

Usage:
    python fetch_wmg_stock.py
"""

import sys
from datetime import datetime, timedelta

try:
    import yfinance as yf
    import pandas as pd
except ImportError:
    print("Error: Required packages not installed.")
    print("Please install dependencies: pip install -r requirements.txt")
    sys.exit(1)


# Define companies to analyze
COMPANIES = {
    'WMG': {
        'name': 'Warner Music Group',
        'ticker': 'WMG',
        'currency': 'USD'
    },
    'UMG': {
        'name': 'Universal Music Group',
        'ticker': 'UMG.AS',  # Euronext Amsterdam
        'currency': 'EUR'
    },
    'SONY': {
        'name': 'Sony Group Corporation',
        'ticker': 'SONY',
        'currency': 'USD'
    }
}


def fetch_stock_data(ticker, company_name):
    """Fetch stock data for a given ticker over the past 90 days."""
    # Calculate date range (90 days ago to today)
    end_date = datetime.now()
    start_date = end_date - timedelta(days=90)

    try:
        # Create ticker object
        stock = yf.Ticker(ticker)

        # Fetch historical data
        hist = stock.history(start=start_date, end=end_date)

        if hist.empty:
            print(f"Warning: No data available for {ticker} ({company_name})")
            return None

        # Get current/latest price
        current_price = hist['Close'].iloc[-1]
        current_date = hist.index[-1].date()

        # Calculate 90-day statistics
        start_price = hist['Close'].iloc[0]
        high_90d = hist['High'].max()
        low_90d = hist['Low'].min()
        avg_volume = hist['Volume'].mean()

        # Calculate percentage change
        pct_change = ((current_price - start_price) / start_price) * 100

        # Determine trend
        if pct_change > 5:
            trend = "Upward"
        elif pct_change < -5:
            trend = "Downward"
        else:
            trend = "Sideways"

        # Calculate volatility (standard deviation of daily returns)
        daily_returns = hist['Close'].pct_change()
        volatility = daily_returns.std() * 100

        return {
            'ticker': ticker,
            'name': company_name,
            'current_price': current_price,
            'current_date': current_date,
            'start_price': start_price,
            'start_date': hist.index[0].date(),
            'high_90d': high_90d,
            'low_90d': low_90d,
            'pct_change': pct_change,
            'trend': trend,
            'volatility': volatility,
            'avg_volume': avg_volume,
            'data_points': len(hist)
        }

    except Exception as e:
        print(f"Error fetching data for {ticker} ({company_name}): {str(e)}")
        return None


def format_company_output(data, currency):
    """Format individual company stock data for display."""
    if not data:
        return

    currency_symbol = '$' if currency == 'USD' else '€'

    print(f"Current Price: {currency_symbol}{data['current_price']:.2f} (as of {data['current_date']})")
    print()

    print("90-Day Performance:")
    print("-" * 60)
    print(f"  Starting Price:     {currency_symbol}{data['start_price']:.2f} ({data['start_date']})")
    print(f"  Current Price:      {currency_symbol}{data['current_price']:.2f} ({data['current_date']})")
    print(f"  Change:             {currency_symbol}{data['current_price'] - data['start_price']:.2f} ({data['pct_change']:+.2f}%)")
    print(f"  Trend:              {data['trend']}")
    print()
    print(f"  90-Day High:        {currency_symbol}{data['high_90d']:.2f}")
    print(f"  90-Day Low:         {currency_symbol}{data['low_90d']:.2f}")
    print(f"  Volatility:         {data['volatility']:.2f}%")
    print(f"  Avg Daily Volume:   {data['avg_volume']:,.0f}")
    print(f"  Data Points:        {data['data_points']} trading days")
    print()


def print_comparison_table(all_data):
    """Print a comparison table of all companies."""
    print("=" * 80)
    print("COMPETITOR COMPARISON (90-DAY PERFORMANCE)")
    print("=" * 80)
    print()

    # Table header
    print(f"{'Company':<30} {'Ticker':<10} {'Price':<15} {'90-Day Chg':<12} {'Trend':<10}")
    print("-" * 80)

    # Table rows
    for key, company in COMPANIES.items():
        data = all_data.get(key)
        if data:
            currency_symbol = '$' if company['currency'] == 'USD' else '€'
            price_str = f"{currency_symbol}{data['current_price']:.2f}"
            change_str = f"{data['pct_change']:+.2f}%"
            print(f"{company['name']:<30} {key:<10} {price_str:<15} {change_str:<12} {data['trend']:<10}")
        else:
            print(f"{company['name']:<30} {key:<10} {'N/A':<15} {'N/A':<12} {'N/A':<10}")

    # BMG (private company)
    print(f"{'BMG':<30} {'N/A':<10} {'N/A (Private)':<15} {'N/A':<12} {'N/A':<10}")
    print()


def print_competitive_analysis(all_data):
    """Print competitive analysis based on the data."""
    print("=" * 80)
    print("COMPETITIVE ANALYSIS")
    print("=" * 80)
    print()

    wmg_data = all_data.get('WMG')
    umg_data = all_data.get('UMG')
    sony_data = all_data.get('SONY')

    if not wmg_data:
        print("Unable to perform analysis - WMG data unavailable")
        return

    print(f"Warner Music Group Performance: {wmg_data['pct_change']:+.2f}% over 90 days")
    print()

    # Compare with competitors
    if umg_data:
        diff_umg = wmg_data['pct_change'] - umg_data['pct_change']
        if diff_umg > 0:
            print(f"✓ WMG outperformed Universal Music Group by {diff_umg:.2f} percentage points")
        elif diff_umg < 0:
            print(f"✗ WMG underperformed Universal Music Group by {abs(diff_umg):.2f} percentage points")
        else:
            print(f"= WMG performed in line with Universal Music Group")
    else:
        print("⚠ Universal Music Group data unavailable for comparison")

    print()

    if sony_data:
        diff_sony = wmg_data['pct_change'] - sony_data['pct_change']
        if diff_sony > 0:
            print(f"✓ WMG outperformed Sony Group by {diff_sony:.2f} percentage points")
        elif diff_sony < 0:
            print(f"✗ WMG underperformed Sony Group by {abs(diff_sony):.2f} percentage points")
        else:
            print(f"= WMG performed in line with Sony Group")
    else:
        print("⚠ Sony data unavailable for comparison")

    print()

    # Industry trend analysis
    changes = [data['pct_change'] for data in all_data.values() if data]
    if len(changes) > 1:
        avg_change = sum(changes) / len(changes)
        if all(c < 0 for c in changes):
            print("Industry Trend: Broad decline across music industry stocks")
        elif all(c > 0 for c in changes):
            print("Industry Trend: Broad growth across music industry stocks")
        else:
            print("Industry Trend: Mixed performance across music industry stocks")
        print(f"Average change across analyzed companies: {avg_change:+.2f}%")

    print()
    print("Note: BMG is privately held and not included in public market analysis")
    print()


def main():
    """Main execution function."""
    print("=" * 80)
    print("MUSIC INDUSTRY STOCK ANALYSIS")
    print("Fetching 90-day stock data for WMG and competitors...")
    print("=" * 80)
    print()

    all_data = {}

    # Fetch data for each company
    for key, company in COMPANIES.items():
        print(f"Fetching data for {company['name']} ({company['ticker']})...")
        data = fetch_stock_data(company['ticker'], company['name'])
        if data:
            all_data[key] = data
        print()

    # Display individual company details
    for key, company in COMPANIES.items():
        data = all_data.get(key)
        if data:
            print("=" * 80)
            print(f"{company['name'].upper()} ({key})")
            print("=" * 80)
            print()
            format_company_output(data, company['currency'])

    # Display comparison table
    print_comparison_table(all_data)

    # Display competitive analysis
    print_competitive_analysis(all_data)

    print("=" * 80)
    print("Note: For news analysis and deeper insights, please use web search")
    print("      to find recent developments affecting these stocks.")
    print("=" * 80)
    print()

    return 0 if all_data else 1


if __name__ == "__main__":
    sys.exit(main())
