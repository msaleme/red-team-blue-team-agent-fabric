# Discord Security Scan Bot

A standalone Discord bot that lets agent developers scan MCP endpoints for security vulnerabilities directly from Discord.

> **Note:** This is a standalone bot script, NOT integrated with OpenClaw's Discord. It's meant for agent developer community servers.

## Features

- `!scan <url>` - Run 5 quick MCP security tests against any endpoint
- Results posted as a rich Discord embed with grade (A-F) and per-test pass/fail
- Rate limiting: 1 scan per user per 5 minutes
- Links to full harness for deeper analysis

## Quick Start

### 1. Create a Discord Bot

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Click "New Application" and name it (e.g., "Agent Security Scanner")
3. Go to **Bot** tab, click "Add Bot"
4. Under **Privileged Gateway Intents**, enable **Message Content Intent**
5. Copy the bot token

### 2. Invite the Bot

Go to **OAuth2 > URL Generator**:
- Scopes: `bot`
- Bot Permissions: `Send Messages`, `Embed Links`, `Read Message History`
- Copy the generated URL and open it to invite the bot to your server

### 3. Configure & Run

```bash
# Clone the repo
git clone https://github.com/msaleme/red-team-blue-team-agent-fabric.git
cd red-team-blue-team-agent-fabric

# Install dependencies
pip install discord.py python-dotenv

# Set up token
cp scripts/.env.example .env
# Edit .env and paste your bot token

# Run the bot
python scripts/discord_scan_bot.py
```

### 4. Use in Discord

```
!scan https://my-mcp-server.example.com/mcp
!scan_help
```

## Tests Run

The quick scan runs 5 core MCP security tests:

| Test | What It Checks |
|------|---------------|
| MCP-001: Tool List Integrity | Suspicious or poisoned tool listings |
| MCP-002: Description Injection | Prompt injection via tool descriptions |
| MCP-004: Capability Escalation | Unauthorized capability negotiation |
| MCP-006: Protocol Downgrade | Forced use of older, insecure protocol |
| MCP-008: Malformed Input Handling | Error handling for malformed JSON-RPC |

## Grading Scale

| Grade | Pass Rate | Meaning |
|-------|-----------|---------|
| A | 5/5 | All tests pass - looking good |
| B | 4/5 | Minor issues found |
| C | 3/5 | Moderate security concerns |
| D | 2/5 | Significant vulnerabilities |
| F | 0-1/5 | Critical security issues |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DISCORD_BOT_TOKEN` | Yes | Your Discord bot token |

## Rate Limiting

- 1 scan per user per 5 minutes
- Configurable via `RATE_LIMIT_SECONDS` in the script
- Prevents abuse of the scanning endpoint

## Deployment

### Running as a Service (systemd)

```ini
# /etc/systemd/system/agent-scan-bot.service
[Unit]
Description=Agent Security Scan Discord Bot
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/red-team-blue-team-agent-fabric
ExecStart=/usr/bin/python3 scripts/discord_scan_bot.py
Restart=always
EnvironmentFile=/path/to/.env

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable agent-scan-bot
sudo systemctl start agent-scan-bot
```

### Docker

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install discord.py python-dotenv
CMD ["python", "scripts/discord_scan_bot.py"]
```

```bash
docker build -t agent-scan-bot .
docker run -d --env-file .env agent-scan-bot
```

## Full Harness

The Discord bot runs a quick 5-test subset. For comprehensive testing (100+ tests across MCP, A2A, L402, identity, and more):

```bash
pip install agent-security-harness
agent-security test mcp --url https://your-server.com/mcp
```

See the [main README](../README.md) for full documentation.
