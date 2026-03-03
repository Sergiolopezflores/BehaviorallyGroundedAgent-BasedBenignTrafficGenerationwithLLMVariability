Appendix – Implementation Notes, Planner Contract, and Profile Action Catalogues

This appendix consolidates implementation-level artifacts that support replication without expanding the main methodological narrative:

Per-profile action catalogues

Automation and analysis software stack

Policy hyperparameters and state management

Constrained planner interface (LLM contract)

Versioned components checklist

1. Profile Policy Parameterization and State Management

This section documents the policy hyperparameters operationalizing

𝜋
(
⋅
∣
𝑃
)
π(⋅∣P).

Even when byte-level determinism is not expected, these parameters ensure procedural reproducibility.

Policy Hyperparameters
Profile	Action Distribution	N_max	Delay / Dwell	State Window (K) & Resampling (M)	Fallback
Regular user	Categorical over {search_google, open_url, watch_youtube, show_email, play_streaming, use_twitter}	fill	δ ∈ [0,25] s	K=fill, M=fill	Safe open/search
Gamer	Deterministic scaffold + stochastic perturbations	fill	Update waits & pacing	K=fill, M=fill	Resume loop
Administrator	Categorical over {SSH, SFTP, ICMP, DNS, HTTP probes}	fill	Inter-command delays	K=fill, M=fill	Alternate host/action

Fields marked fill must be instantiated from configuration constants.

2. Per-Profile Action Catalogues
Regular User (Web-Centric)

The agent operates through browser automation driven by a high-level planner.

Actions:

Request navigation decision from planner

Navigate to selected page

Watch streaming content

Watch YouTube

Interact with social media (X)

Access webmail

Randomized pauses and scrolling

Gamer (Interactive + VoIP)

The gamer agent executes gameplay with concurrent real-time communication.

Sequence:

Launch Steam and Discord

Apply updates if present

Launch game and execute recorded interactions with randomness

Generate synthetic non-informational audio for VoIP

Network Administrator (Internal Management)

The administrator agent operates inside a host-only topology.

Actions:

TCP connectivity checks

SSH interactive sessions

Monitoring commands

Log inspection

SFTP transfers

ICMP / HTTP service probes

3. Constrained Planner Interface (Regular User Profile)

The LLM is used only for high-level navigation decisions.
All packet-level behavior emerges from real application execution.

The planner must return a schema-valid JSON object.

Invalid outputs are rejected.

Allowed Action Types

search_google

open_url

watch_youtube

show_email

play_streaming

use_twitter

JSON Schema (Enforced at Runtime)
{
  "type": "object",
  "required": ["type", "delay"],
  "properties": {
    "type": {
      "type": "string",
      "enum": [
        "search_google",
        "open_url",
        "watch_youtube",
        "show_email",
        "play_streaming",
        "use_twitter"
      ]
    },
    "delay": { "type": "integer", "minimum": 0, "maximum": 25 },
    "term": { "type": "string", "minLength": 1, "maxLength": 120 },
    "url": { "type": "string", "pattern": "^https?://.+" },
    "search": { "type": "string", "minLength": 1, "maxLength": 120 }
  },
  "additionalProperties": false
}
Example Valid Outputs
{"type":"search_google","term":"latest news on network security","delay":15}
{"type":"open_url","url":"https://www.bbc.com/mundo","delay":10}
{"type":"watch_youtube","search":"introductory Python programming","delay":18}
Example Invalid Outputs
{"type":"open_url","term":"somewhere","delay":10}
{"type":"watch_youtube","delay":60}
{"type":"hack_wifi","delay":10}
Fallback Policy

If schema validation fails:

Action is discarded

A predefined safe action is executed

The invalid output is logged

This ensures execution safety and auditability.

LLM Configuration Record (Example)
llm:
  provider: groq
  model: <MODEL_ID_EXACT>
  temperature: 0.7
  top_p: 0.9
  max_tokens: 64
  stop: ["\n\n"]
  retries: 2
  timeout_s: 10

artifacts:
  prompt_version: web_planner_v1
  prompt_sha256: <SHA256_OF_TEMPLATE>
  schema_version: planner_schema_v1
4. Automation and Analysis Software Stack
Component	Role
Selenium + undetected_chromedriver	Browser automation
requests	Planner/API invocation
pyautogui / pynput	Gameplay interaction
subprocess	External app orchestration
sounddevice / soundfile	Synthetic VoIP audio
paramiko	SSH/SFTP automation
Scapy + Matplotlib	PCAP parsing and analysis
5. Versioned Components Checklist

To ensure reproducibility, record exact versions:

Component	Version
VirtualBox	fill
Windows build	fill
Linux build	fill
Browser	fill
Steam	fill
Discord	fill
Game build	fill
Wireshark	fill
tcpdump	fill
Agent Git commit	fill
