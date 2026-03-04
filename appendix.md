# Appendix A. Run Manifest Field Checklist

To support procedural reproducibility and post-hoc auditing, the frame-
work can optionally record a per-run manifest capturing environment prove-
nance, capture provenance, and run metadata. The manifest is intended to
make experimental conditions auditable without implying byte-level trace
determinism.

| Component | Exact version / identifier |
|----------|-----------------------------|
| Hypervisor | Virtualization platform name and exact version (e.g., Oracle VM VirtualBox vX.Y.Z). |
| Host platform | Host OS and hardware summary (CPU model, RAM). |
| VM image ID  | Immutable identifier for the VM image used in the run (e.g., export hash). |
| Snapshot ID | Identifier of the clean snapshot restored before the run. |
| Guest OS build  | OS distribution/build and kernel/build number (where applicable). |
| Virtual hardware  | vCPU, RAM, storage allocation, NIC model. |
| Network configuration | Network mode (NAT / host-only / internal), addressing, and topology ID. |
| Capture point | Where capture is performed (guest NIC or virtual gateway, when applicable). |
| Capture interface | Interface name (e.g., Ethernet X, eth0) and link-layer type. |
| Capture toolchain | Tool name and exact version (Wireshark / tcpdump), invocation parameters. |
| Agent versioning | Agent code version (e.g., Git commit) and configuration profile ID. |
| Run parameters | Profile, duration T , run index, random seed (if applicable), start timestamp. |
| Artifacts | Output filenames and cryptographic checksums for PCAP and manifest. |
| LLM configuration (if applicable) | Model identifier, decoding parameters, prompt/template version, and action schema version. |


# Appendix B. Implementation Notes, Planner Contract, and Profile Action Catalogues

This appendix consolidates implementation-level artifacts that support
replication without expanding the main methodological narrative: (i) per-
profile action catalogues and (ii) the automation and analysis software stack,
including the constrained planner interface and policy parameterization. 

---
<!--
## Profile Policy Parameterization and State Management

Table B.7 reports the policy hyperparameters that operationalize π(· | P)
(Section 4.2.1). Reporting these values makes the behavioral assumptions
explicit and supports reproducibility at the mechanism level, even when byte-
level trace determinism is not expected.

### Policy Hyperparameters

| Profile | Action-type distribution w_P | N_max | Delay / dwell ranges | State window K and resampling M | Fallback policy |
|----------|-----------------------------|--------|----------------------|----------------------------------|-----------------|
| Regular user | Categorical over {buscar_google, abrir_url, mirar_youtube, revisar_correo, ver_streaming, usar_twitter} with weights fill | fill | δ in [0,25] s; dwell/scroll bounds fill | K=fill targets; M=fill attempts | Safe open/search from allowlisted targets (fill) |
| Gamer | Deterministic session scaffold with stochastic perturbations (event jitter/drop/idle injection) parameters fill | fill | Update waits and session pacing fill | K=fill recent segments; M=fill | Resume baseline loop / idle segment (fill) |
| Administrator | Categorical over host-actions (SSH, SFTP, ICMP, DNS, HTTP probes) with weights fill | fill | Typing/inter-command delays fill | K=fill hosts; M=fill | Select alternative host/action class (fill) |

Fields marked **fill** should be instantiated with the exact values used in the experiments.

---
-->

## Per-Profile Action Catalogues

### Regular user (web-centric)

Regular user (web-centric).. The regular-user agent operates exclusively through
browser interaction driven by a high-level planner and randomized interac-
tion timing. The action catalogue comprises:
1. Request a high-level navigation decision from the planner.
2. Navigate to web pages conditioned on the selected browsing profile.
3. Watch streaming content.
4. Watch YouTube content.
5. Interact with social media (e.g., X).
6. Access webmail.
7. Emulate human interaction through randomized pauses and scrolling.  

---

### Gamer (interactive + VoIP)

Gamer (interactive + VoIP).. The gamer agent executes a controlled game-play session with concurrent real-time communication. The operational se-
quence comprises:
1. Launch the required clients (Steam and Discord/VoIP).
2. Wait for and apply client/game updates when present (typically TCP-
dominant bursts).
3. Launch the game and execute recorded interaction traces with injected
randomness.
4. Generate non-informational synthetic audio to drive VoIP traffic with-
out sensitive content.

---

### Network Administrator (internal management)

Network administrator (internal management).. The administrator agent em-
ulates benign management activity within a host-only topology. The action
catalogue comprises:
1. TCP connectivity checks to managed hosts.
2. Establish interactive SSH sessions to hosts.
3. Execute system and network monitoring commands.
4. Inspect and partially read system logs.
5. Transfer files via SFTP.
6. Generate ICMP and HTTP traffic from the administrator host for
reachability and service checks.

---

## Constrained Planner Interface (Regular-User Profile)

The regular-user agent uses a language-model-backed planner only to
instantiate high-level navigation decisions (e.g., what to search for, which
benign URL to open, and how long to dwell), while all packet- and protocol-
level properties remain an emergent result of executing real applications and
network stacks. To make this component reviewable and reproducible, the
planner is restricted to a fixed action space and must return a schema-valid
JSON object. The agent validates each response before execution and logs
planner configuration and template identifiers as part of the run provenance.

The figure below provides an implementation-oriented decomposition of the regular-user agent.
The planner is isolated to a narrow decision boundary (schema-constrained action proposals), while orchestration and browser automation are responsible for execution, timing perturbations, and session-budget enforcement.
Traffic generation is therefore not a separate synthesis step; it is the observable outcome of executing real applications under these constraints.


<p align="center">
<img src="images/RegularUser.png" alt="RegularUser" width="600">
</p>
---

### Action space and parameters.
Planner outputs select an action type (type)
and an execution delay in seconds (delay), optionally providing an action-
specific parameter such as a query term (term), a URL (url), or a content
search string (search). The permitted action types correspond to the pro-
file’s browsing repertoire (search, open URL, consume content, and access
common services).

### Machine-validated output schema.
The Listing below defines the schema enforced at
runtime. Only schema-compliant outputs are eligible for execution; invalid
responses are rejected and handled via the fallback policy described below.


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
```
### Representative valid outputs.
Listing below shows examples that satisfy the schema
and illustrate how semantic variability is introduced at the action layer
(choice of intent and parameters) while remaining within profile constraints.

```json
{"type":"search_google","termin":"latest network security incidents","delay":12}
{"tipo":"search_google","termino":"weather forecast Malaga","delay":9}
{"tipo":"open_url","url":"https://www.wikipedia.org/","delay":8}
{"tipo":"watch_youtube","search":"computer networks lecture","delay":17}
{"tipo":"show_correo","delay":14}
```

### Representative invalid outputs and failure modes.
Listing below provides common invalid patterns (wrong fields, out-of-range parameters, or non-permitted
actions). These cases motivate enforcing a strict schema boundary.

```json
{"type":"open_url","term":"somewhere","delay":10}
{"type":"watch_youtube","delay":60}
{"type":"hack_wifi","delay":10}
```

The examples above are invalid, respectively, because they omit a required
field for the selected action type (url), violate the allowed range for delay,
or use an action type not contained in the permitted enum.



### Validation and fallback policy.
Planner outputs are parsed and validated
against Listing 1 before execution. If validation fails, the agent performs up
to Rretry re-queries using the same prompt template and the current interac-
tion context. If all retries fail, the agent executes a predefined safe fallback
action drawn from an allow listed set (e.g., opening a benign landing page
or issuing a generic non-sensitive query). In all cases, the raw model output,
the validation error (when applicable), the selected fallback, and the promp-
t/template identifier are logged to the run manifest to preserve provenance
and to enable post-hoc auditing.

Related agentic LLM frameworks in other safety-critical settings employ
explicit quality-assurance loops to iteratively verify and correct structured
outputs; in our case, this role is covered by bounded re-query attempts plus
a deterministic safe fallback [22].


### Decoding configuration and versioned prompts.
To support procedural reproducibility, each run records (i) the exact model identifier, (ii) decoding
parameters, and (iii) the version identifiers of the prompt template and ac-
tion schema. The listing below illustrates a minimal configuration record in YAML
form.

```json
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
```

## Appendix B.4. Automation and analysis software stack

| Component | Role in the framework |
|----------|-----------------------------|
| Selenium + undetected_chromedriver | Browser automation for the regular-user profile |
| Requests | Planner/API invocation |
| Pyautogui / pynput | Gameplay interaction |
| Subprocess | Launch external applications |
| Sounddevice / soundfile | Synthetic VoIP audio |
| Paramiko | SSH/SFTP automation |
| Scapy + Matplotlib | PCAP parsing and analysis | 








[22] Yu Yao, Salil Bhatnagar, Markus Mazzola, Vasileios Belagiannis, Igor
Gilitschenski, Luigi Palmieri, Simon Razniewski, and Marcel Hallgar-
ten. Agents-llm: Augmentative generation of challenging traffic scenar-
ios with an agentic llm framework. In 2025 IEEE/RSJ International
Conference on Intelligent Robots and Systems (IROS), pages 18400–
18407. IEEE, 2025.

