# Prompt used to create this skill

## First Shot

```
Help me create a skill (named wmg-stock) that will provide the stock price for Warner Music Group (WMG) and analyze the trends over the past 90 days. You can utilize a web search to find the current price and the trend over the past 90 days. Also, be sure to include a search of the high profile and important news that likely impacted the stock - again, you should use a web search for this. The output from this skill should be the current price, analysis of the stock price over the previous 90 days and then a bulleted list of the important and impactful news. For the news, please provide a 1-2 sentence summary only for each impacting topic, but provide 1-2 web URLs where you got that information. If you need to create any scripts for this skill, please use Python and ensure you put that script into the "scripts/" directory for the skill. Please create a new directory for the skill under the "pksecure_io-claude/skills/" directory, but do not add this skill into the "pksecure_io-claude/.claude/skills" nor in the global "~/.claude/skills" folder at this time.
```

## Second Shot

```
Can you please modify the wmg-stock skill to also analyze the direct competitors' stock price and performance over the same time period. The main competitors to WMG are Universal Music Group, Sony Music Entertainment and BMG.
```