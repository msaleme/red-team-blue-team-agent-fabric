#!/usr/bin/env python3
"""Discord Security Scan Bot

A standalone Discord bot that lets agent developers scan MCP endpoints
directly from Discord using the Agent Security Harness.

Usage:
    # In Discord, type:
    !scan https://my-mcp-server.example.com/mcp

    # The bot runs 5 quick MCP security tests and posts results as an embed.

Setup:
    1. Create a Discord bot at https://discord.com/developers/applications
    2. Copy your bot token
    3. Create .env with DISCORD_BOT_TOKEN=your_token_here
    4. pip install discord.py python-dotenv
    5. python scripts/discord_scan_bot.py

Requires: Python 3.10+, discord.py, python-dotenv
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from protocol_tests.version import get_harness_version

HARNESS_VERSION = get_harness_version()

try:
    import discord
    from discord.ext import commands
except ImportError:
    print("Error: discord.py is required. Install with: pip install discord.py")
    sys.exit(1)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # .env loading is optional if token is set directly


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")
RATE_LIMIT_SECONDS = 300  # 5 minutes per user
REPO_URL = "https://github.com/msaleme/red-team-blue-team-agent-fabric"
PROJECT_ROOT = Path(__file__).parent.parent

# Quick scan test subset (same as free_scan)
QUICK_SCAN_TESTS = [
    {
        "id": "MCP-001",
        "name": "Tool List Integrity",
        "description": "Checks for suspicious or poisoned tool listings",
    },
    {
        "id": "MCP-002",
        "name": "Description Injection",
        "description": "Tests for prompt injection via tool descriptions",
    },
    {
        "id": "MCP-004",
        "name": "Capability Escalation",
        "description": "Attempts unauthorized capability negotiation",
    },
    {
        "id": "MCP-006",
        "name": "Protocol Downgrade",
        "description": "Attempts to force older, insecure protocol version",
    },
    {
        "id": "MCP-008",
        "name": "Malformed Input Handling",
        "description": "Sends malformed JSON-RPC to test error handling",
    },
]


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Simple per-user rate limiter."""

    def __init__(self, cooldown_seconds: int = RATE_LIMIT_SECONDS):
        self.cooldown = cooldown_seconds
        self._last_use: dict[int, float] = {}

    def check(self, user_id: int) -> tuple[bool, int]:
        """Check if user can scan. Returns (allowed, seconds_remaining)."""
        now = time.time()
        last = self._last_use.get(user_id, 0)
        elapsed = now - last
        if elapsed < self.cooldown:
            remaining = int(self.cooldown - elapsed)
            return False, remaining
        return True, 0

    def record(self, user_id: int):
        """Record a scan for rate limiting."""
        self._last_use[user_id] = time.time()


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def validate_url(url: str) -> str | None:
    """Validate URL for SSRF safety.

    Returns None if valid, or an error message if blocked.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return "Malformed URL"

    # Only allow http and https schemes
    if parsed.scheme not in ("http", "https"):
        return f"Blocked scheme: {parsed.scheme} (only http/https allowed)"

    hostname = parsed.hostname
    if not hostname:
        return "No hostname in URL"

    # Resolve hostname to IP and check for internal addresses
    try:
        resolved_ips = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return f"Cannot resolve hostname: {hostname}"

    for family, _type, _proto, _canonname, sockaddr in resolved_ips:
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return f"Invalid resolved IP: {ip_str}"

        # Block private, loopback, link-local, and reserved ranges
        if addr.is_private:
            return f"Blocked private/internal IP: {ip_str}"
        if addr.is_loopback:
            return f"Blocked loopback IP: {ip_str}"
        if addr.is_link_local:
            return f"Blocked link-local IP: {ip_str}"
        if addr.is_reserved:
            return f"Blocked reserved IP: {ip_str}"

        # Explicit cloud metadata check (AWS/GCP/Azure)
        if ip_str in ("169.254.169.254", "fd00:ec2::254"):
            return f"Blocked cloud metadata IP: {ip_str}"

    return None


def run_quick_scan(url: str) -> list[dict]:
    """Run 5 quick MCP tests against the given URL.

    Returns a list of result dicts with keys: id, name, passed, details
    """
    # SSRF validation
    ssrf_error = validate_url(url)
    if ssrf_error:
        return [{
            "id": "SSRF-BLOCK",
            "name": "URL Validation",
            "passed": False,
            "details": ssrf_error,
        }]

    results: list[dict] = []

    # Use secure temporary file for report (avoids symlink attacks on /tmp)
    report_fd, report_path = tempfile.mkstemp(suffix=".json", prefix="discord_scan_")
    os.close(report_fd)

    try:
        cmd = [
            sys.executable, "-m", "protocol_tests.mcp_harness",
            "--transport", "http",
            "--url", url,
            "--report", report_path,
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(PROJECT_ROOT),
        )

        if os.path.exists(report_path):
            with open(report_path) as f:
                report = json.load(f)

            quick_ids = {t["id"] for t in QUICK_SCAN_TESTS}
            for r in report.get("results", []):
                if r.get("test_id") in quick_ids:
                    results.append({
                        "id": r["test_id"],
                        "name": r.get("name", "Unknown"),
                        "passed": r.get("passed", False),
                        "details": r.get("details", "")[:100],
                    })

            if results:
                return results
    except subprocess.TimeoutExpired:
        pass  # Fall through to connection-error results
    except Exception:
        pass  # Fall through to connection-error results
    finally:
        # Clean up temporary report file
        try:
            os.unlink(report_path)
        except OSError:
            pass

    # If harness didn't produce results, indicate connection issue
    for test in QUICK_SCAN_TESTS:
        results.append({
            "id": test["id"],
            "name": test["name"],
            "passed": False,
            "details": f"Could not connect to {url} - verify the endpoint is reachable",
        })

    return results


def compute_grade(results: list[dict]) -> str:
    """Compute letter grade from scan results."""
    if not results:
        return "F"

    passed = sum(1 for r in results if r.get("passed", False))
    total = len(results)
    ratio = passed / total

    if ratio >= 1.0:
        return "A"
    elif ratio >= 0.8:
        return "B"
    elif ratio >= 0.6:
        return "C"
    elif ratio >= 0.4:
        return "D"
    else:
        return "F"


def grade_color(grade: str) -> int:
    """Return Discord embed color for grade."""
    colors = {
        "A": 0x2ECC71,  # Green
        "B": 0x3498DB,  # Blue
        "C": 0xF1C40F,  # Yellow
        "D": 0xE67E22,  # Orange
        "F": 0xE74C3C,  # Red
    }
    return colors.get(grade, 0x95A5A6)


# ---------------------------------------------------------------------------
# Discord Bot
# ---------------------------------------------------------------------------

intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)
rate_limiter = RateLimiter()


@bot.event
async def on_ready():
    print(f"Bot connected as {bot.user} (ID: {bot.user.id})")
    print(f"Serving {len(bot.guilds)} guild(s)")
    print("Ready to scan! Use: !scan <url>")


@bot.command(name="scan")
async def scan_command(ctx: commands.Context, url: str = ""):
    """Scan an MCP endpoint for security vulnerabilities.

    Usage: !scan <url>
    Example: !scan https://my-server.com/mcp
    """
    # Validate URL
    if not url:
        await ctx.send(
            embed=discord.Embed(
                title="Usage",
                description="`!scan <url>`\n\nExample: `!scan https://my-server.com/mcp`",
                color=0x3498DB,
            )
        )
        return

    url_pattern = re.compile(r"^https?://[^\s]+$")
    if not url_pattern.match(url):
        await ctx.send(
            embed=discord.Embed(
                title="Invalid URL",
                description="Please provide a valid HTTP or HTTPS URL.",
                color=0xE74C3C,
            )
        )
        return

    # Rate limit check
    allowed, remaining = rate_limiter.check(ctx.author.id)
    if not allowed:
        await ctx.send(
            embed=discord.Embed(
                title="Rate Limited",
                description=f"Please wait **{remaining}s** before scanning again.\n"
                           f"Limit: 1 scan per user per {RATE_LIMIT_SECONDS // 60} minutes.",
                color=0xE67E22,
            )
        )
        return

    # Record usage
    rate_limiter.record(ctx.author.id)

    # Send "scanning" message
    scanning_embed = discord.Embed(
        title="Scanning...",
        description=f"Running 5 quick MCP security tests against:\n`{url}`",
        color=0x3498DB,
    )
    scanning_embed.set_footer(text="This usually takes 10-30 seconds")
    scanning_msg = await ctx.send(embed=scanning_embed)

    # Run scan in thread pool to avoid blocking
    loop = asyncio.get_event_loop()
    results = await loop.run_in_executor(None, run_quick_scan, url)

    # Compute grade
    grade = compute_grade(results)
    passed = sum(1 for r in results if r.get("passed", False))
    total = len(results)

    # Build results embed
    result_embed = discord.Embed(
        title=f"Security Scan: Grade {grade}",
        description=f"**Target:** `{url}`\n**Result:** {passed}/{total} tests passed",
        color=grade_color(grade),
        timestamp=datetime.now(timezone.utc),
    )

    # Add per-test results
    for r in results:
        emoji = "\u2705" if r.get("passed") else "\u274C"
        name = f"{emoji} {r['id']}: {r['name']}"
        value = r.get("details", "No details")[:100]
        result_embed.add_field(name=name, value=value, inline=False)

    # Footer with repo link
    result_embed.set_footer(
        text=f"Agent Security Harness v{HARNESS_VERSION} | Full suite: {REPO_URL}"
    )

    # Add link to full harness
    result_embed.add_field(
        name="\U0001F50D Want deeper analysis?",
        value=f"Run the full harness (100+ tests) locally:\n"
              f"```\npip install agent-security-harness\n"
              f"agent-security test mcp --url {url}\n```\n"
              f"[GitHub Repository]({REPO_URL})",
        inline=False,
    )

    # Edit the scanning message with results
    await scanning_msg.edit(embed=result_embed)


@bot.command(name="scan_help")
async def scan_help_command(ctx: commands.Context):
    """Show help for the security scan bot."""
    embed = discord.Embed(
        title="Agent Security Scan Bot",
        description="Scan MCP endpoints for common security vulnerabilities.",
        color=0x3498DB,
    )
    embed.add_field(
        name="Usage",
        value="`!scan <url>` - Run 5 quick security tests",
        inline=False,
    )
    embed.add_field(
        name="Tests Run",
        value="\n".join(f"- **{t['id']}**: {t['name']}" for t in QUICK_SCAN_TESTS),
        inline=False,
    )
    embed.add_field(
        name="Grading",
        value="**A** = 5/5 pass | **B** = 4/5 | **C** = 3/5 | **D** = 2/5 | **F** = 0-1/5",
        inline=False,
    )
    embed.add_field(
        name="Rate Limit",
        value=f"1 scan per user per {RATE_LIMIT_SECONDS // 60} minutes",
        inline=False,
    )
    embed.set_footer(text=f"Powered by Agent Security Harness v{HARNESS_VERSION} | {REPO_URL}")
    await ctx.send(embed=embed)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    if not BOT_TOKEN:
        print("Error: DISCORD_BOT_TOKEN not set.")
        print("Set it in your environment or create a .env file.")
        print("See .env.example for details.")
        sys.exit(1)

    print("Starting Agent Security Scan Bot...")
    bot.run(BOT_TOKEN)


if __name__ == "__main__":
    main()
