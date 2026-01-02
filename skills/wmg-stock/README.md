# WMG Stock Analysis Skill

This skill provides comprehensive stock analysis for Warner Music Group (ticker: WMG), including current price information, 90-day trend analysis, competitor comparison, and identification of impactful news events.

## Competitors Analyzed

This skill analyzes WMG's performance relative to its main competitors:

- **Universal Music Group (UMG)** - Listed on Euronext Amsterdam (ticker: UMG.AS)
- **Sony Group Corporation (SONY)** - Parent company of Sony Music Entertainment, listed on NYSE
- **BMG** - Privately held (not publicly traded, noted as N/A in comparisons)

## External Documentation and Resources

### Warner Music Group
- [Warner Music Group Investor Relations](https://investors.wmg.com/)
- [Yahoo Finance - WMG](https://finance.yahoo.com/quote/WMG)
- [Google Finance - WMG](https://www.google.com/finance/quote/WMG:NASDAQ)

### Competitors
- [Universal Music Group - Investor Relations](https://www.universalmusic.com/company/)
- [Yahoo Finance - UMG](https://finance.yahoo.com/quote/UMG.AS)
- [Sony Group Corporation - Investor Relations](https://www.sony.com/en/SonyInfo/IR/)
- [Yahoo Finance - SONY](https://finance.yahoo.com/quote/SONY)

### Tools
- [yfinance Documentation](https://pypi.org/project/yfinance/) - Python library for fetching stock data

## Usage

### Example Prompts

When using this skill with Claude Code, try prompts like:

- "Analyze WMG stock"
- "Show me the Warner Music Group stock performance"
- "Get the current WMG stock price and recent news"
- "What's happening with Warner Music Group stock?"

### Skill Activation

The skill uses web search to gather:

1. **Current stock price** - Latest trading price and date for WMG
2. **90-day trend analysis** - Performance over the past quarter
3. **Competitor performance** - UMG and Sony stock performance over the same period
4. **Competitive comparison** - How WMG performed relative to competitors
5. **Impactful news** - Major events affecting stock price

### Expected Output

The skill will provide a formatted report containing:

```
## Warner Music Group (WMG) Stock Analysis

**Current Price:** $XX.XX (as of [Date])

### 90-Day Trend Analysis
[Detailed analysis of stock performance including percentage change,
volatility patterns, and key price movements]

### Competitor Comparison (90-Day Performance)
[Comparison table showing WMG, UMG, and SONY performance]
[Competitive analysis explaining how WMG performed relative to peers]

### Impactful News & Events
- Bulleted list of 3-5 major news items
- Each with 1-2 sentence summary
- Source URLs provided for verification
```

## Key Assets

This skill does not use custom assets.

## scripts/

The `scripts/` directory contains an optional Python script for fetching stock data programmatically using the yfinance API.

### fetch_wmg_stock.py

Alternative method for fetching WMG and competitor stock data using Python and the yfinance API instead of web search.

**Requirements:**
- Python 3.7 or higher
- Dependencies listed in `requirements.txt`

**Setup (using virtual environment - recommended):**

```bash
cd skills/wmg-stock/scripts

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

**Usage:**

```bash
python fetch_wmg_stock.py
```

**Output:**
The script provides comprehensive competitive analysis including:

**Individual Company Analysis:**
- Current stock price and date
- Starting price from 90 days ago
- Percentage change and trend direction
- 90-day high and low
- Volatility metrics
- Average daily trading volume

**Competitor Comparison:**
- Side-by-side comparison table of all companies
- Competitive performance analysis
- Industry trend identification
- Relative performance metrics

**Companies Analyzed:**
- Warner Music Group (WMG) - NASDAQ
- Universal Music Group (UMG) - Euronext Amsterdam
- Sony Group Corporation (SONY) - NYSE
- BMG - Noted as private (no stock data available)

**Note:** The Python script provides quantitative stock data and competitive comparison but does NOT include news analysis. For complete analysis (including news), use the skill through Claude Code which leverages web search.

**Deactivating virtual environment:**
```bash
deactivate
```

## References

This skill does not use reference files.

## Development Status

**Stage:** `dev` (version 0.2)

**Recent Updates:**
- Added competitor analysis for UMG and Sony
- Implemented comparative performance metrics
- Enhanced Python script with multi-company support

This skill is in active development. It has been tested with basic use cases but may have edge cases or limitations when:
- Market data is delayed or unavailable
- News sources have limited coverage
- Stock has unusual trading patterns
- International stock data (UMG on Euronext) has limited availability

## Limitations

- Relies on web search availability and quality
- Stock prices may be delayed (typically 15-20 minutes for free sources)
- News analysis is limited to publicly available sources
- Historical data accuracy depends on source reliability
- UMG data in euros may require currency conversion for direct comparison
- BMG data not available (privately held company)

## Future Enhancements

Potential improvements for future versions:
- Customizable time periods (30, 60, 180 days)
- Technical indicator analysis (RSI, MACD, moving averages)
- Comparison with market indices (S&P 500, NASDAQ)
- Additional music industry competitors (SPOT, TMUS, LSEG)
- Sentiment analysis of news articles
- Currency conversion for easier UMG comparison
- Historical earnings data overlay
