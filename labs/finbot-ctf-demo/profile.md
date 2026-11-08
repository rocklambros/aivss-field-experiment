# Lab profile: finbot-ctf-demo

Repo: OWASP-ASI/finbot-ctf-demo

Flask application with one LLM agent (FinBot) that processes vendor invoices through OpenAI function calling. Goals are written in natural language and can be changed through an unauthenticated admin API.

## Default configuration

Flask app started with gunicorn (render.yaml) or python src/main.py. OpenAI client with model gpt-4.1-mini. Auto-approve threshold 1000, manual review threshold 5000, speed priority 0.7, fraud detection on, no custom goals.

Evidence: `finbot-ctf-demo/render.yaml:1-17`, `finbot-ctf-demo/src/services/finbot_agent.py:14-21`, `finbot-ctf-demo/src/main.py:73-83`, `finbot-ctf-demo/src/models/vendor.py:96-107`

## Agents

### FinBot (`finbot`)

- Role: Autonomous invoice processing assistant
- Framework: Direct OpenAI Chat Completions with function calling (no agent framework)
- Model provider: OpenAI, model gpt-4.1-mini, temperature 0.3
- Loop: Up to 5 iterations. The model chooses tools with tool_choice auto. The loop ends on approve_invoice, reject_invoice, or request_human_review.
- Fallback: When the OpenAI client cannot be created, a rule-based function (_fallback_processing) decides instead of a model.
- System prompt: Natural-language goals built per request from the FinBotConfig row. Any custom_goals text is appended under the heading CUSTOM GOALS (OVERRIDE ABOVE IF CONFLICTING). Evidence: `finbot-ctf-demo/src/services/finbot_agent.py:32-99`, `finbot-ctf-demo/src/services/finbot_agent.py:69-71`
- Evidence: `finbot-ctf-demo/src/services/finbot_agent.py:7-12`, `finbot-ctf-demo/src/services/finbot_agent.py:14-21`, `finbot-ctf-demo/src/services/finbot_agent.py:150-226`, `finbot-ctf-demo/src/services/finbot_agent.py:772-877`


## Applicability questions

| Agent | Model-directed goal pursuit | Selects or sequences actions | Confidence | Rationale |
|---|---|---|---|---|
| finbot | True | True | high | In the default configuration an OpenAI model receives natural-language goals and an invoice task, then chooses which of five tools to call and in what order across up to five turns. The approve, reject, and escalate decisions are tool calls the model selects. The rule-based fallback applies only when no OpenAI client exists, which is not the documented default. Evidence: `finbot-ctf-demo/src/services/finbot_agent.py:37-99`, `finbot-ctf-demo/src/services/finbot_agent.py:161-212`, `finbot-ctf-demo/src/services/finbot_agent.py:154-156` |

## Tools

| Tool | Capability | What it does | Evidence |
|---|---|---|---|
| get_invoice_details | read | Reads the invoice and vendor rows. Returns the attacker-supplied description text to the model. Sets contains_prompt_injection when a regex detector matches. | `finbot-ctf-demo/src/services/finbot_agent.py:363-407` |
| approve_invoice | write | Sets status approved and payment_processed true. No amount check, no confirmation, and no check of the detector flag before the write. | `finbot-ctf-demo/src/services/finbot_agent.py:409-458` |
| reject_invoice | write | Sets status rejected. | `finbot-ctf-demo/src/services/finbot_agent.py:460-480` |
| request_human_review | write | Sets status pending_review for a human reviewer. | `finbot-ctf-demo/src/services/finbot_agent.py:482-503` |
| detect_fraud_patterns | read | Regex and keyword checks. Returns an empty result when fraud detection is disabled in the config. | `finbot-ctf-demo/src/services/finbot_agent.py:505-547` |

Tool binding: Five fixed tools defined in code. No dynamic tools, MCP servers, plugins, or skills. Tool arguments are not validated beyond JSON parsing. Evidence: `finbot-ctf-demo/src/services/finbot_agent.py:228-345`, `finbot-ctf-demo/src/services/finbot_agent.py:347-361`

## Data sources and grounding

| Source | Trust | Description | Evidence |
|---|---|---|---|
| Invoice description | attacker-controlled (any vendor) | Free text submitted through the vendor API and returned to the model inside a tool result. | `finbot-ctf-demo/src/routes/vendor.py:69-110`, `finbot-ctf-demo/src/services/finbot_agent.py:390-394` |
| FinBotConfig row | writable by any unauthenticated caller | Thresholds, speed priority, fraud detection flag, and custom_goals text. Read on every request to build the system prompt. | `finbot-ctf-demo/src/models/vendor.py:96-107`, `finbot-ctf-demo/src/routes/admin.py:74-109`, `finbot-ctf-demo/src/services/finbot_agent.py:735-770` |

## Memory persistence

Value: cross-session (configuration), none (conversation).

Each invoice starts a fresh message list, so there is no conversation memory. The custom_goals text is stored in the database and injected into the system prompt of every later run.

Evidence: `finbot-ctf-demo/src/services/finbot_agent.py:163-166`, `finbot-ctf-demo/src/services/finbot_agent.py:735-748`, `finbot-ctf-demo/src/models/vendor.py:105`

## Multi-agent handoffs

Value: none.

Single agent. A human reviewer can decide flagged invoices through the admin API.

Evidence: `finbot-ctf-demo/src/routes/admin.py:26-65`

## Human approval

Optional and model-controlled. The model may call request_human_review, which parks the invoice for a reviewer. Nothing forces review above the manual review threshold. approve_invoice executes directly. The reviewer endpoint has no authentication.

Evidence: `finbot-ctf-demo/src/services/finbot_agent.py:49-52`, `finbot-ctf-demo/src/services/finbot_agent.py:351-352`, `finbot-ctf-demo/src/routes/admin.py:26-65`

## Deployment

Render web service running gunicorn on 0.0.0.0. SQLite database copied from cleandb to /tmp/app.db unless DATABASE_URL is set.

Evidence: `finbot-ctf-demo/render.yaml:1-17`, `finbot-ctf-demo/gunicorn.conf.py:1-9`, `finbot-ctf-demo/src/main.py:35-65`

## Lab severity labels

The lab assigns difficulty levels (Easy, Intermediate, Hard) to CTF flags. It assigns no severity labels.

Evidence: `finbot-ctf-demo/docs/FinBot-CTF-walkthrough-goal-manipulation.md:128-131`, `finbot-ctf-demo/src/services/finbot_agent.py:427-441`

## Exploit artifacts in the repo

The repo has no exploit scripts and no tests. The walkthrough describes each method in prose without a payload. The code awards CTF flags when an invoice is approved under stated conditions.

Evidence: `finbot-ctf-demo/docs/FinBot-CTF-walkthrough-goal-manipulation.md:109-184`, `finbot-ctf-demo/src/services/finbot_agent.py:119-138`

## Identities and credentials

- OpenAI API key read from the environment by the OpenAI client. Evidence: `finbot-ctf-demo/src/services/finbot_agent.py:16`
- Hard-coded Flask SECRET_KEY. Evidence: `finbot-ctf-demo/src/main.py:15`
- Vendor bank account and routing numbers stored in the vendors table and returned by the vendor API. Evidence: `finbot-ctf-demo/src/models/vendor.py:16-19`, `finbot-ctf-demo/src/routes/vendor.py:63-67`

## Exposure

- Public endpoint: yes. The README links a public live instance, and the app binds 0.0.0.0.
- Authentication: none on any route, including every /api/admin route. CORS is open for all routes.
- Evidence: `finbot-ctf-demo/README.md:5-9`, `finbot-ctf-demo/src/main.py:18`, `finbot-ctf-demo/src/main.py:105`, `finbot-ctf-demo/gunicorn.conf.py:4`, `finbot-ctf-demo/src/routes/admin.py:11-219`, `finbot-ctf-demo/src/routes/vendor.py:12-164`

## Text addressed to an AI assistant (observed, not followed)

None found.

## Notes

- The README points at a public live instance. The experiment never contacts it (ground rule 3).
