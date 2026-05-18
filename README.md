# RealAgentID

![RealAgentID](assets/logo.png)

**Blockchain-grade security at inference speed.**

The trust layer for AI agent networks. RealAgentID gives every AI agent a cryptographic identity - preventing spoofing, replay attacks, and unauthorized
commands before they reach your infrastructure.

> "As agentic AI redefines what's possible, the boldest organizations will set the pace of transformation." -Databricks, 2026 State of AI Agents

## The Problem

AI agents are executing trades, routing medical decisions, processing legal contracts, and running R&D pipelines. Nobody knows if the agent sending
the command is actually who it says it is.

## The Solution

RealAgentID is the missing trust layer - cryptographic identity for verification for AI agents  that operates at subsecond latency, invisible to your
real time inference pipeline.

## Why Cryptographic Trust - Not Platform Trust

Every major platform will tell you their agents are governed. None of them can prove it without asking you to trust their infrastructure first. 

RealAgenID is different. The identity verification is cyrptographic - the math either checks out or it doesn't. No vendor. No cloud console. No MCP workaround required.

Platforms like Oracle and Gemini Enterprise govern what agents do inside their cloud. 

RealAgentID governs what agents *are*
- cryptographically, anywhere.*

## What It Does

- Generates Ed25519 cryptographic keypairs per agent
- Signs and verifies messages with sub-millisecond latency
- Blocks replay attacks via Redis TTL nonces
- Detects payload tampering in real time
- Logs all events to a tamper-evident audit trail
- Tracks behavioral patterns via local AI analysis

## Quick Start

'''bash
git clone https://github.com/
RealAgentID/RealAgentID.git
cd RealAgentID
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 tests/test_full_run.py

## SDK

from realagentid import Agent

agent = Agent(name="signal_gen", role="signal_gen")
agent.keygen()
agent.register()
signed = agent.sign({"action": "buy", "asset": "BTC"}, channel="signal:btc")
verified = agent.verify(signed)

## CLI

python3 cli/main.py keygen --name my_agent
python3 cli/main.py register --agent-id my_agent --pubkey ./keys/my_agent.pem --role worker
python3 cli/main.py list
python3 cli/main.py sign --agent-id my_agent --message "hello" --privkey ./keys/my_agent_private.pem --channel tasks:default
python3 cli/main.py audit

## Verticals

Finance - trade signal verification, strategy scoring, SEC/FINRA audit trails

Healthcare - clinical trial matching, revenue cycle management, R&D pipeline integrity

Legal - precedent based agent coaching, contract execution verification

Research - verified research intelligence, reproducible AI agent workflows

## Requirements

Python 3.12+

Redis

## Setup Redis

sudo apt install redis-server -y
sudo service redis start
redis-cli ping

## First Production Implementation

[TrailStax](https://github.com/TrailStax/StaxVault) is the first production implementation of RealAgentID - append-only, hash-chained audit trails and code commit registry for AI agents, built on this protocol.

## Licensing

RealAgentID core is MIT licensed and free forever. Enterprise adapters and the Control Center are available under a commercial license. 
Contact support@realagentid.io for enterprise inquiries.
