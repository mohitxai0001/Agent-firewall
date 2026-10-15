# Agent Firewall

**Stop Infinite AI Loops. Protect Your API Budget.**

Agent Firewall is a drop-in proxy for autonomous AI agents. It intercepts runaway loops, enforces hard budget caps, and monitors live agent spend *before* the LLM provider bills you.

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-green)

---

## The Problem
When building autonomous AI agents (using frameworks like LangChain, AutoGen, or custom loops), a single hallucination can cause the agent to get stuck in an infinite loop. If left unchecked, the agent will rapidly consume tokens, resulting in massive unexpected API bills.

## The Solution
Agent Firewall sits between your agent and your LLM provider (OpenAI, Google Gemini, Anthropic, etc.). 
1. Your agent calls the Firewall.
2. The Firewall checks your active session budget and step limits.
3. If limits are exceeded, the Firewall intercepts the request and returns an `HTTP 429 Too Many Requests`.
4. If limits are safe, the Firewall calculates the live cost and proxies the request to the LLM.

---

## Features
* **Drop-in Replacement:** Works out-of-the-box with standard OpenAI SDKs. Just change the `base_url`.
* **Budget Caps:** Set strict USD limits per session.
* **Loop Prevention:** Kill sessions that exceed a defined number of continuous steps.
* **Multi-Model Support:** Powered by [LiteLLM](https://github.com/BerriAI/litellm), supporting 100+ LLMs (OpenAI, Gemini, Claude, Groq).
* **Live Developer Dashboard:** Real-time UI to monitor intercepted sessions and active projects.

---

## Quick Start (Local)

### 1. Clone & Install
```bash
git clone [https://github.com/mohitxai0001/agent-firewall.git](https://github.com/mohitxai0001/agent-firewall.git)
cd agent-firewall
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
pip install -r requirements.txt