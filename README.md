# Agentic AI for Cyber Security: Building Autonomous Security Assistants

My hands-on learning record from the NPTEL+ workshop **Agentic AI for Cyber Security: Building Autonomous Security Assistants**, covering **Agentic AI in Cyber Security** and **Multi-Agent Security Automation**. This repository preserves instructor-provided Python exercises, setup instructions, sample logs, and my PowerShell execution transcript.

[Official NPTEL+ workshop page](https://elearn.nptel.ac.in/product-page/agentic-ai-for-cyber-security-building-autonomous-security-assistants)

The exercises progress from a basic tool-calling agent to a multi-agent Security Operations Centre (SOC) assistant using Ollama, CVE enrichment, MITRE ATT&CK context, and prompt-injection checks.

## Workshop modules

| Module | Duration | Topics and learning outcomes |
| --- | --- | --- |
| Agentic AI in Cyber Security | 2.5 hours | Agent fundamentals and lifecycle; building a security assistant; analyzing logs; integrating CVE lookup, threat intelligence, and MITRE ATT&CK into agent workflows. |
| Multi-Agent Security Automation | 2.5 hours | Multi-agent systems; building safer agents; orchestrating security investigation pipelines; building a SOC assistant for cybersecurity events. |

The module outline describes the workshop curriculum; the file guide below identifies the implementations included here.

## Exercises

| File | Purpose |
| --- | --- |
| `Programs/agent1.py` | Basic model tool call using a greeting tool. |
| `Programs/agent2.py` | Return the tool result to the model for a final response. |
| `Programs/agent3.py` | Interpret deterministic security log findings. |
| `Programs/agent4.py` | Separate evidence, inference, unknowns, and recommendations. |
| `Programs/agent4a.py` | Intentionally vulnerable prompt-injection comparison. |
| `Programs/agent5.py` | Inspect tool output and construct a hardened data boundary. |
| `Programs/agent6.py` | Enrich product/version evidence with NVD CVE information. |
| `Programs/agent7.py` | Enrich suspicious activity with MITRE ATT&CK context. |
| `Programs/agent8.py` | Coordinate CVE and MITRE agents, inspect combined data, and validate the final assessment. |
| `Programs/tools/` | Detection and enrichment tools, sample logs, and a MITRE lookup test. |
| `Programs/test_*.py` | Workshop checks and integration demonstrations. |

## Setup on Windows / PowerShell

Install Python and Ollama using the instructor's setup notes. The original guide mentions both Python 3.13 and 3.14; the commands below use whichever Python installation the `py` launcher selects. The workshop transcript records execution with Python 3.14. Dependency versions in `requirements.txt` are not pinned and do not reproduce an exact environment.

From the repository root:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
ollama pull llama3.2:3b
ollama list
```

Keep Ollama running locally. The examples use `llama3.2:3b`; CVE and MITRE lookups also require internet access.

## Run the exercises

Run from `Programs` so the workshop's relative sample-log paths resolve:

```powershell
cd Programs
python agent1.py
python agent2.py
python agent3.py tools/security.log
python agent4.py tools/security_injection.log
python agent4a.py tools/security_injection.log
python agent5.py tools/security_injection.log
python agent6.py tools/vulnerability_event.log
python agent7.py tools/vulnerability_event.log
python agent8.py tools/vulnerability_event.log
```

Example workshop checks:

```powershell
python test_agent5.py
python test_agent6.py
python test_agent7.py
python test_agent8.py
python test_cve_lookup.py
python test_ollama.py
python tools/test_mitre_lookup.py
```

Some checks call a local model or external services; they are not an isolated offline test suite. Model responses and live intelligence may vary.

## Execution record and limitations

- [Instructor setup instructions](Agentic%20AI%20Security%20Workshop%20Setup.txt)
- [My PowerShell commands and captured output](Agentic%20AI%20Security%20Workshop%20PS.txt)
- [Workshop module outline](docs/workshop-modules.png)

The transcript preserves installation issues, model responses, and failures observed during the workshop. In particular, the recorded Agent 8 run rejected the model's output during deterministic validation. Captured model output can contain unsupported claims or incorrect remediation advice; it is a historical learning record, not verified security guidance.

`agent4a.py` is deliberately vulnerable for comparison. Prompt rules, pattern matching, and output validation in the other examples illustrate defensive techniques rather than guaranteeing protection. Use these exercises in a controlled learning environment.

## Attribution

The workshop was offered through NPTEL+. The Python scripts and setup instructions were supplied by the workshop instructor. My contribution here is executing the exercises, retaining the PowerShell learning record, and organizing/documenting this repository. This is my personal workshop learning repository and is not an official NPTEL+ repository.

No open-source license is added: this repository does not grant rights to instructor-owned material. Original authors retain their rights.

The local virtual environment and generated Python caches are excluded. Source scripts, the three sample logs, and both text records are preserved unchanged.
