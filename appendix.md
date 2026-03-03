# Appendix  
## Implementation Notes, Planner Contract, and Profile Action Catalogues

This appendix consolidates implementation-level artifacts that support replication without expanding the main methodological narrative:

1. Per-profile action catalogues  
2. Automation and analysis software stack  
3. Compact checklist of versioned components  

---

## Profile Policy Parameterization and State Management

This section reports the policy hyperparameters that operationalize:

pi(a | P)

Reporting these values makes the behavioral assumptions explicit and supports reproducibility at the mechanism level, even when byte-level trace determinism is not expected.

### Policy Hyperparameters

| Profile | Action-type distribution w_P | N_max | Delay / dwell ranges | State window K and resampling M | Fallback policy |
|----------|-----------------------------|--------|----------------------|----------------------------------|-----------------|
| Regular user | Categorical over {buscar_google, abrir_url, mirar_youtube, revisar_correo, ver_streaming, usar_twitter} with weights fill | fill | δ in [0,25] s; dwell/scroll bounds fill | K=fill targets; M=fill attempts | Safe open/search from allowlisted targets (fill) |
| Gamer | Deterministic session scaffold with stochastic perturbations (event jitter/drop/idle injection) parameters fill | fill | Update waits and session pacing fill | K=fill recent segments; M=fill | Resume baseline loop / idle segment (fill) |
| Administrator | Categorical over host-actions (SSH, SFTP, ICMP, DNS, HTTP probes) with weights fill | fill | Typing/inter-command delays fill | K=fill hosts; M=fill | Select alternative host/action class (fill) |

Fields marked **fill** should be instantiated with the exact values used in the experiments.

---

## Per-Profile Action Catalogues

### Regular user (web-centric)

The regular-user agent operates exclusively through browser interaction driven by a high-level planner and randomized interaction timing.

Actions:

1. Request a high-level navigation decision from the planner  
2. Navigate to web pages conditioned on the selected browsing profile  
3. Watch streaming content  
4. Watch YouTube content  
5. Interact with social media (e.g., X)  
6. Access webmail  
7. Emulate human interaction through randomized pauses and scrolling  

---

### Gamer (interactive + VoIP)

The gamer agent executes a controlled gameplay session with concurrent real-time communication.

Sequence:

1. Launch the required clients (Steam and Discord/VoIP)  
2. Wait for and apply client/game updates when present  
3. Launch the game and execute recorded interaction traces with injected randomness  
4. Generate non-informational synthetic audio to drive VoIP traffic  

---

### Network Administrator (internal management)

The administrator agent emulates benign management activity within a host-only topology.

Actions:

1. TCP connectivity checks to managed hosts  
2. Establish interactive SSH sessions  
3. Execute system and network monitoring commands  
4. Inspect and partially read system logs  
5. Transfer files via SFTP  
6. Generate ICMP and HTTP traffic for reachability and service checks  

---

## Constrained Planner Interface (Regular-User Profile)

The regular-user agent uses a language-model-backed planner only to instantiate high-level navigation decisions (e.g., what to search for, which benign URL to open, and how long to dwell).

All packet- and protocol-level properties remain an emergent result of executing real applications and network stacks.

The planner must return a schema-valid JSON object.

---

### Allowed Action Types

- search_google  
- open_url  
- watch_youtube  
- show_email  
- play_streaming  
- use_twitter  

---

### Enforced JSON Schema

```json
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
```json
{"type":"search_google","termin":"latest network security incidents","delay":12}
{"tipo":"search_google","termino":"weather forecast Malaga","delay":9}
{"tipo":"open_url","url":"https://www.wikipedia.org/","delay":8}
{"tipo":"watch_youtube","search":"computer networks lecture","delay":17}
{"tipo":"show_correo","delay":14}

{"type":"open_url","term":"somewhere","delay":10}
{"type":"watch_youtube","delay":60}
{"type":"hack_wifi","delay":10}

Invalid because:

Missing required fields

Delay outside allowed range

Action type not in permitted enum



Validation and Fallback Policy

Planner outputs are validated against the enforced JSON schema before execution.

If validation fails:

The agent performs up to R_retry re-queries

If all retries fail, a predefined safe fallback action is executed

Raw output, validation error, fallback action, and prompt ID are logged

Decoding Configuration and Versioned Prompts

Each run records:

Model identifier

Decoding parameters

Prompt version

Prompt SHA256

Schema version

Example:
llm:
  provider: groq
  model: <MODEL_ID_EXACTO>
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

Automation and Analysis Software Stack
Component	Role
Selenium + undetected_chromedriver	Browser automation
requests	Planner/API invocation
pyautogui / pynput	Gameplay interaction
subprocess	Launch external applications
sounddevice / soundfile	Synthetic VoIP audio
paramiko	SSH/SFTP automation
Scapy + Matplotlib	PCAP parsing and analysis
Versioned Components Checklist

Record exact versions:

Component	Exact version
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
