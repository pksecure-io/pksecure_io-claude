---
name: wmg-stock
description: Provides Warner Music Group (WMG) stock price, 90-day trend analysis, competitor comparison, and impactful news events
license: Apache-2.0
compatibility: Designed for Claude Code. Requires internet access for web search functionality.
metadata:
  author: Paul Kincaid <paul@pksecure.io>
  version: "0.2"
  stage: dev
---

# WMG Stock Analysis Skill

This skill provides comprehensive stock analysis for Warner Music Group (ticker: WMG) including current price, 90-day trend analysis, competitor comparison, and impactful news events.

## Competitors Analyzed

- **Universal Music Group (UMG)** - Listed on Euronext Amsterdam
- **Sony Group Corporation (SONY)** - Parent company of Sony Music Entertainment, listed on NYSE
- **BMG** - Privately held (not publicly traded, will note as N/A in analysis)

## Instructions

When this skill is activated, perform the following steps:

### Step 1: Gather Current Stock Price

Use web search to find the current Warner Music Group (WMG) stock price. Search for:
- "WMG stock price today"
- "Warner Music Group stock current price"

Extract the most recent price and trading date.

### Step 2: Analyze 90-Day Trend

Use web search to find historical stock performance over the past 90 days:
- "WMG stock 90 day chart"
- "Warner Music Group stock 3 month performance"
- "WMG stock trend past quarter"

Analyze the data to identify:
- Overall trend (upward, downward, or sideways)
- Percentage change over the period
- Significant price movements or volatility
- High and low points during the period

### Step 3: Analyze Competitor Performance

Use web search to gather 90-day performance data for WMG's main competitors:

**Universal Music Group (UMG):**
- "UMG stock price 90 day performance"
- "Universal Music Group stock 3 month trend"

**Sony Group Corporation (SONY):**
- "SONY stock price 90 day performance"
- "Sony stock 3 month trend"

For each competitor, gather:
- Current stock price
- 90-day percentage change
- Overall trend direction
- Notable developments if any

**Note:** BMG is privately held and does not have publicly traded stock. Note this in the analysis.

### Step 4: Identify Impactful News

Use web search to find high-profile news that likely impacted the stock:
- "WMG Warner Music Group news past 90 days"
- "Warner Music Group earnings news"
- "WMG stock news important developments"

Focus on:
- Earnings reports
- Executive changes
- Major deals or acquisitions
- Industry developments
- Regulatory changes
- Analyst upgrades/downgrades

### Step 5: Format Output

Present the information in the following format:

```
## Warner Music Group (WMG) Stock Analysis

**Current Price:** $XX.XX (as of [Date])

### 90-Day Trend Analysis

[2-3 paragraphs analyzing the stock's performance over the past 90 days, including:
- Overall trend direction and percentage change
- Key price movements and volatility patterns
- Notable support/resistance levels if applicable
- Context for the performance (market conditions, sector performance)]

### Competitor Comparison (90-Day Performance)

| Company | Ticker | Current Price | 90-Day Change | Trend |
|---------|--------|---------------|---------------|-------|
| Warner Music Group | WMG | $XX.XX | +/-X.X% | Upward/Downward/Sideways |
| Universal Music Group | UMG | €XX.XX | +/-X.X% | Upward/Downward/Sideways |
| Sony Group Corp. | SONY | $XX.XX | +/-X.X% | Upward/Downward/Sideways |
| BMG | N/A | N/A (Private) | N/A | N/A |

**Competitive Analysis:**
[1-2 paragraphs comparing WMG's performance to its competitors:
- How WMG performed relative to UMG and Sony
- Whether the trend is industry-wide or company-specific
- Any notable differences in performance
- Context for competitive positioning]

### Impactful News & Events

- **[News Topic 1]**: [1-2 sentence summary of the event and its impact]
  - Source: [URL 1]
  - Source: [URL 2]

- **[News Topic 2]**: [1-2 sentence summary of the event and its impact]
  - Source: [URL 1]
  - Source: [URL 2]

[Continue for 3-5 most impactful news items]
```

## Important Notes

- Always include the date/time of the current price
- Cite all sources with URLs
- Focus on news that had measurable impact on stock price
- If stock data is unavailable or limited, clearly indicate this
- Provide context for stock movements by comparing to competitors
- Note that UMG is listed in euros on Euronext Amsterdam
- Note that SONY represents Sony Group Corporation, the parent company of Sony Music Entertainment
- Note that BMG is privately held and has no public stock data available

## Error Handling

If you cannot find sufficient information:
- Clearly state what data is missing
- Provide whatever partial information is available
- Suggest alternative approaches (e.g., checking financial websites directly)
