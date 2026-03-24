# seclint

Security linter for AI prompts. Age-appropriate ratings (6+, 12+, 16+, 18+), topic guidance, safety classification. No LLM required.

## How It Works

```
prompt -> seclint (classify) -> rating + flags

"Help me with homework"          -> 6+  (safe)
"Write a thriller story"         -> 12+ (mild violence themes)
"Explain network security tools" -> 16+ (security/hacking context)
"[explicit content]"             -> 18+ (blocked or flagged)
```

## Quick Start

### Install

```bash
go install github.com/mikeshogin/seclint/cmd/seclint@latest
```

### CLI Usage

```bash
# Rate a prompt
echo "Help me write a school essay about history" | seclint rate
# Output: {"rating": "6+", "safe": true, "flags": []}

# Check if prompt passes a threshold
echo "Explain SQL injection attacks" | seclint check --max-rating 12
# Exit 1 (rating is 16+, exceeds threshold)

# Filter mode - block or sanitize
echo "Some prompt text" | seclint filter --policy strict
```

### HTTP Server

```bash
# Start server
seclint serve 8091

# Rate a prompt
curl -X POST http://localhost:8091/rate -d "prompt text here"

# Health check
curl http://localhost:8091/health
```

## Rating System

| Rating | Description | Examples |
|--------|-------------|---------|
| 6+ | Safe for all ages | homework, general knowledge, creative writing |
| 12+ | Mild themes | thriller plots, competitive topics, mild conflict |
| 16+ | Mature themes | security tools, medical details, business strategy |
| 18+ | Adult only | explicit content, weapons, drugs, violence |
| BLOCKED | Policy violation | illegal activities, harm, exploitation |

## Classification Signals

- **Keyword matching** - domain-specific word lists per category
- **Context analysis** - surrounding words modify severity
- **Intent detection** - educational vs malicious use
- **Combination rules** - certain word combinations escalate rating

## Integration with Ecosystem

```
prompt -> seclint (safe?) -> promptlint (route) -> agent -> archlint (quality)
              |                                                       |
           BLOCK if unsafe                                    costlint (track)
```

### As pre-filter before promptlint

```bash
# Pipeline: guard first, then route
echo "prompt" | seclint check --max-rating 16 && echo "prompt" | promptlint analyze
```

### As ccproxy hook

seclint can run as a pre-routing hook in ccproxy - block or flag prompts before they reach any model.

## Related Projects

- [promptlint](https://github.com/mikeshogin/promptlint) - prompt complexity scoring and model routing
- [costlint](https://github.com/mikeshogin/costlint) - token cost tracking and optimization
- [archlint](https://github.com/mshogin/archlint) - code architecture analysis

See [ECOSYSTEM.md](ECOSYSTEM.md) for full integration map.

## Contributing

1. Fork and send a PR
2. Open an issue with ideas
3. Barter: review exchange
