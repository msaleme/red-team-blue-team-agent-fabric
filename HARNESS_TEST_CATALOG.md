# Agent Security Harness — Canonical Test Catalog

**Source repo:** msaleme/red-team-blue-team-agent-fabric
**Generated:** `scripts/generate_test_catalog.py` at commit `5d4ccd5`
**Test count:** 611 unique test IDs across 45 registered harness modules (44 contain test IDs; `community_runner.py` is a plugin runner with none of its own)
**Purpose:** Ground-truth reference for any bot, agent, or human representing the harness in public posts, comments, or discussions. Cite only tests listed here. Do not invent IDs or statistics.

## Rules for Citation
1. Test IDs must match verbatim.
2. Do not attribute a finding to a test unless the test's description above actually covers that finding.
3. Numeric statistics (e.g. "X tool calls") must appear in the repo or published reports. If not present, do not cite them.
4. When in doubt, say "we have tests in this area" and skip specifics.
5. **Absence from this catalog is evidence only if the catalog is current.** Check the commit above against `main` before claiming that no test covers something. This file is generated; regenerate it rather than editing it by hand.

## Tests


### A2A Protocol (`protocol_tests/a2a_harness.py`) — 13 tests

```
A2A-001 | Agent Card Discovery | protocol_tests/a2a_harness.py:349
A2A-002 | Agent Card Spoofing via Message Metadata | protocol_tests/a2a_harness.py:350
A2A-003 | Agent Card Path Traversal | protocol_tests/a2a_harness.py:351
A2A-004 | Unauthorized Task Access/Cancel | protocol_tests/a2a_harness.py:352
A2A-005 | Task Message Injection (Prompt + Data + File) | protocol_tests/a2a_harness.py:353
A2A-006 | Task State Manipulation | protocol_tests/a2a_harness.py:354
A2A-007 | Push Notification URL Redirect | protocol_tests/a2a_harness.py:355
A2A-008 | Unauthorized Skill Request | protocol_tests/a2a_harness.py:356
A2A-009 | Artifact Content Type Abuse | protocol_tests/a2a_harness.py:357
A2A-010 | Malformed Request Handling | protocol_tests/a2a_harness.py:358
A2A-011 | Undocumented Method Enumeration | protocol_tests/a2a_harness.py:359
A2A-012 | Cross-Context Data Leakage | protocol_tests/a2a_harness.py:360
A2A-013 | Agent Card Limitations Field Verification | protocol_tests/a2a_harness.py:361
```

### Advanced Attacks (`protocol_tests/advanced_attacks.py`) — 10 tests

```
CHAIN-001 | Credential → Identity → Cloud Pivot (3-Step Chain) | protocol_tests/advanced_attacks.py:501
CHAIN-002 | SaaS Lateral Movement (Doc → Email → Finance) | protocol_tests/advanced_attacks.py:544
JAIL-001 | Jailbreak Persistence (Same Session + Cross-Session) | protocol_tests/advanced_attacks.py:646
JAIL-002 | Roleplay-Based Jailbreak (4 Personas) | protocol_tests/advanced_attacks.py:697
POLY-001 | Polymorphic Injection (10 Unique Payloads) | protocol_tests/advanced_attacks.py:238
POLY-002 | Encoding Evasion (8 Variants) | protocol_tests/advanced_attacks.py:275
RECON-001 | Attack Surface Self-Mapping (5 Queries) | protocol_tests/advanced_attacks.py:590
STATE-001 | Trust-Building → Escalation (8 turns) | protocol_tests/advanced_attacks.py:332
STATE-002 | Playbook Injection Bypass (Mexico Breach Pattern) | protocol_tests/advanced_attacks.py:408
STATE-003 | Guardrail Erosion (8-Step Progressive Escalation) | protocol_tests/advanced_attacks.py:450
```

### agent_data_injection.py (`protocol_tests/agent_data_injection.py`) — 3 tests

```
ADI-001 | a forged provenance field inside an untrusted content body. | protocol_tests/agent_data_injection.py:310
ADI-002 | a fabricated prior tool call and result inside a response body. | protocol_tests/agent_data_injection.py:326
ADI-003 | content mimicking the agent's own context boundary. | protocol_tests/agent_data_injection.py:343
```

### AIUC-1 Compliance (`protocol_tests/aiuc1_compliance_harness.py`) — 12 tests

```
AIUC-C003a | Harmful Content Generation Refusal | protocol_tests/aiuc1_compliance_harness.py:776
AIUC-C003b | Deceptive Content Generation Refusal | protocol_tests/aiuc1_compliance_harness.py:809
AIUC-C004a | Out-of-Scope Execution Refusal | protocol_tests/aiuc1_compliance_harness.py:857
AIUC-C004b | Scope Creep Detection | protocol_tests/aiuc1_compliance_harness.py:905
AIUC-C004c | Authority Impersonation Refusal | protocol_tests/aiuc1_compliance_harness.py:938
AIUC-E001 | Incident Detection Latency | protocol_tests/aiuc1_compliance_harness.py:97
AIUC-E002 | Incident Containment | protocol_tests/aiuc1_compliance_harness.py:538
AIUC-E003 | Incident Audit Trail | protocol_tests/aiuc1_compliance_harness.py:611
AIUC-F002a | Test refusal of chemical weapon synthesis instructions. | protocol_tests/aiuc1_compliance_harness.py:694
AIUC-F002b | Test refusal of biological weapon creation instructions. | protocol_tests/aiuc1_compliance_harness.py:699
AIUC-F002c | Test refusal of radiological/nuclear weapon instructions. | protocol_tests/aiuc1_compliance_harness.py:704
AIUC-F002d | CBRN Dual-Use Detection | protocol_tests/aiuc1_compliance_harness.py:739
```

### AP2 Mandate Chain (`protocol_tests/ap2_harness.py`) — 17 tests

```
AP2-001 | Checkout Hash Tamper | protocol_tests/ap2_harness.py:414
AP2-002 | Stale / Cross-Session Cart | protocol_tests/ap2_harness.py:437
AP2-003 | Amount Cap Escalation (Intent→Cart) | protocol_tests/ap2_harness.py:462
AP2-004 | Merchant Allowlist Constraint | protocol_tests/ap2_harness.py:483
AP2-005 | Line-Item / SKU Constraint | protocol_tests/ap2_harness.py:502
AP2-006 | Unknown Constraint Fail-Closed | protocol_tests/ap2_harness.py:528
AP2-007 | Mandate Chain Link (transaction_id) | protocol_tests/ap2_harness.py:552
AP2-008 | Open-Mandate Substitution (sd_hash) | protocol_tests/ap2_harness.py:575
AP2-009 | Agent Key Forgery (cnf mismatch) | protocol_tests/ap2_harness.py:598
AP2-010 | Missing User Signature (human-present) | protocol_tests/ap2_harness.py:617
AP2-011 | Payment Mandate Replay (jti) | protocol_tests/ap2_harness.py:642
AP2-012 | Expired Payment Mandate | protocol_tests/ap2_harness.py:662
AP2-013 | Double-Spend on Open Mandate | protocol_tests/ap2_harness.py:687
AP2-014 | Symmetric/Keyed-MAC Signature Scheme | protocol_tests/ap2_harness.py:716
AP2-015 | Funding-Instrument Scope Binding | protocol_tests/ap2_harness.py:757
AP2-016 | Premature Credential Release | protocol_tests/ap2_harness.py:789
AP2-017 | vct Exact-Match Enforcement | protocol_tests/ap2_harness.py:814
```

### autogen_harness.py (`protocol_tests/autogen_harness.py`) — 10 tests

```
AG-MS-001 | Agent Impersonation via Name Field | protocol_tests/autogen_harness.py:467
AG-MS-002 | System Config Injection via Spoofed Assistant | protocol_tests/autogen_harness.py:512
AG-MS-003 | HMAC Verification Bypass with Forged Signature | protocol_tests/autogen_harness.py:564
AG-MS-004 | Cross-Conversation Message Replay Attack | protocol_tests/autogen_harness.py:611
AG-NE-001 | Nested Conversation Escape via Fake Terminator | protocol_tests/autogen_harness.py:320
AG-NE-002 | Shared State Poisoning via Nested Context | protocol_tests/autogen_harness.py:368
AG-NE-003 | Local Executor Trust Boundary Bypass | protocol_tests/autogen_harness.py:414
AG-SP-001 | Direct Speaker Override via Prompt Injection | protocol_tests/autogen_harness.py:182
AG-SP-002 | Fake Task Completion to Skip Agents | protocol_tests/autogen_harness.py:228
AG-SP-003 | Security Agent Exclusion via Fake Maintenance | protocol_tests/autogen_harness.py:271
```

### benchmark_integrity_harness.py (`protocol_tests/benchmark_integrity_harness.py`) — 7 tests

```
BI-001 | Agent-Evaluator Isolation Check | protocol_tests/benchmark_integrity_harness.py:110
BI-002 | Reference Answer Leakage | protocol_tests/benchmark_integrity_harness.py:110
BI-003 | Eval Function Injection | protocol_tests/benchmark_integrity_harness.py:110
BI-004 | LLM Judge Prompt Injection | protocol_tests/benchmark_integrity_harness.py:110
BI-005 | String Matching Collision | protocol_tests/benchmark_integrity_harness.py:540
BI-006 | Validator Bypass | protocol_tests/benchmark_integrity_harness.py:620
BI-007 | Self-Reported Results Trust | protocol_tests/benchmark_integrity_harness.py:708
```

### Capability Profile (`protocol_tests/capability_profile_harness.py`) — 10 tests

```
CP-001 | Profile Declaration Presence | protocol_tests/capability_profile_harness.py:376
CP-002 | Filesystem Boundary (COMPUTE_ONLY) | protocol_tests/capability_profile_harness.py:410
CP-003 | Filesystem Boundary (SCRATCH_FS) | protocol_tests/capability_profile_harness.py:444
CP-004 | Network Boundary | protocol_tests/capability_profile_harness.py:480
CP-005 | Package Install Boundary | protocol_tests/capability_profile_harness.py:514
CP-006 | Tool Bridge Boundary | protocol_tests/capability_profile_harness.py:549
CP-007 | Profile Escalation Attempt | protocol_tests/capability_profile_harness.py:597
CP-008 | Cross-Profile Isolation | protocol_tests/capability_profile_harness.py:633
CP-009 | Profile Logging | protocol_tests/capability_profile_harness.py:676
CP-010 | Custom Profile Validation | protocol_tests/capability_profile_harness.py:721
```

### Card-Network Agentic Tokens (`protocol_tests/card_token_harness.py`) — 12 tests

```
CTK-001 | Agent Holder-Key Binding | protocol_tests/card_token_harness.py:322
CTK-002 | Token Merchant Scope | protocol_tests/card_token_harness.py:341
CTK-003 | Per-Transaction Amount Cap | protocol_tests/card_token_harness.py:371
CTK-004 | Cumulative Velocity Cap | protocol_tests/card_token_harness.py:396
CTK-005 | Cryptogram Freshness (counter replay) | protocol_tests/card_token_harness.py:421
CTK-006 | Cryptogram-Amount Binding | protocol_tests/card_token_harness.py:446
CTK-007 | Token Expiry | protocol_tests/card_token_harness.py:465
CTK-008 | Token Revocation / Suspension | protocol_tests/card_token_harness.py:488
CTK-009 | Consent-Policy Binding | protocol_tests/card_token_harness.py:507
CTK-010 | Channel / Domain Binding | protocol_tests/card_token_harness.py:530
CTK-011 | PAN De-Tokenization Protection | protocol_tests/card_token_harness.py:554
CTK-012 | Cross-Network Token Substitution | protocol_tests/card_token_harness.py:577
```

### CBRN Prevention (`protocol_tests/cbrn_harness.py`) — 8 tests

```
CBRN-001 | Direct Knowledge Boundary | protocol_tests/cbrn_harness.py:340
CBRN-002 | Dual-Use Redirection | protocol_tests/cbrn_harness.py:371
CBRN-003 | Multi-Step Synthesis Chain | protocol_tests/cbrn_harness.py:408
CBRN-004 | Tool-Assisted Knowledge Extraction | protocol_tests/cbrn_harness.py:444
CBRN-005 | Academic Framing Bypass | protocol_tests/cbrn_harness.py:472
CBRN-006 | Fiction/Roleplay Framing | protocol_tests/cbrn_harness.py:501
CBRN-007 | Translation/Encoding Bypass | protocol_tests/cbrn_harness.py:535
CBRN-008 | Threshold Testing | protocol_tests/cbrn_harness.py:578
```

### Cloud Agent Platforms (`protocol_tests/cloud_agent_harness.py`) — 25 tests

```
AZR-001 | Tool Definition Override | protocol_tests/cloud_agent_harness.py:420
AZR-002 | Grounding Source Manipulation | protocol_tests/cloud_agent_harness.py:445
AZR-003 | Thread Isolation Bypass | protocol_tests/cloud_agent_harness.py:470
AZR-004 | File Search Poisoning | protocol_tests/cloud_agent_harness.py:498
AZR-005 | Code Interpreter Escape | protocol_tests/cloud_agent_harness.py:524
BRK-001 | Action Group Injection | protocol_tests/cloud_agent_harness.py:262
BRK-002 | Knowledge Base Poisoning | protocol_tests/cloud_agent_harness.py:288
BRK-003 | Session State Exfiltration | protocol_tests/cloud_agent_harness.py:312
BRK-004 | Lambda Function Escape | protocol_tests/cloud_agent_harness.py:336
BRK-005 | Guardrail Bypass via Multi-Turn | protocol_tests/cloud_agent_harness.py:369
SFA-001 | Topic Classification Bypass | protocol_tests/cloud_agent_harness.py:718
SFA-002 | Apex Action Injection | protocol_tests/cloud_agent_harness.py:743
SFA-003 | Record Access Boundary Violation | protocol_tests/cloud_agent_harness.py:769
SFA-004 | Flow Orchestration Escape | protocol_tests/cloud_agent_harness.py:794
SFA-005 | Einstein Trust Layer Bypass | protocol_tests/cloud_agent_harness.py:820
VTX-001 | Tool Parameter Injection | protocol_tests/cloud_agent_harness.py:572
VTX-002 | Datastore Poisoning | protocol_tests/cloud_agent_harness.py:596
VTX-003 | Extension Authentication Bypass | protocol_tests/cloud_agent_harness.py:622
VTX-004 | Cross-Agent Context Leakage | protocol_tests/cloud_agent_harness.py:646
VTX-005 | Webhook Callback Manipulation | protocol_tests/cloud_agent_harness.py:673
WXO-001 | Skill Catalog Injection | protocol_tests/cloud_agent_harness.py:868
WXO-002 | Decision Engine Manipulation | protocol_tests/cloud_agent_harness.py:891
WXO-003 | Integration Credential Leakage | protocol_tests/cloud_agent_harness.py:914
WXO-004 | Workflow Automation Hijack | protocol_tests/cloud_agent_harness.py:937
WXO-005 | Multi-Tenant Isolation | protocol_tests/cloud_agent_harness.py:960
```

### CrewAI CVE Reproduction (`protocol_tests/crewai_cve_harness.py`) — 10 tests

```
CREW-001 | Sandbox Fallback Detection | protocol_tests/crewai_cve_harness.py:500
CREW-002 | Ctypes Payload Coverage (self-test, no target) | protocol_tests/crewai_cve_harness.py:610
CREW-003 | Code Execution Config Audit | protocol_tests/crewai_cve_harness.py:670
CREW-004 | Path Traversal in JSON Loader | protocol_tests/crewai_cve_harness.py:748
CREW-005 | Sensitive File Read Detection | protocol_tests/crewai_cve_harness.py:826
CREW-006 | SSRF Cloud Metadata Detection | protocol_tests/crewai_cve_harness.py:904
CREW-007 | SSRF Internal Service Detection | protocol_tests/crewai_cve_harness.py:975
CREW-008 | SSRF URL Validation Bypass | protocol_tests/crewai_cve_harness.py:1088
CREW-009 | Docker Availability Check Bypass | protocol_tests/crewai_cve_harness.py:1126
CREW-010 | Fallback Sandbox RCE Chain | protocol_tests/crewai_cve_harness.py:1214
```

### Enterprise Platforms (core) (`protocol_tests/enterprise_adapters.py`) — 31 tests

```
AQ-001 | Data Source Boundary Escape (S3 + Confluence) | protocol_tests/enterprise_adapters.py:499
AQ-002 | IAM Role Escalation | protocol_tests/enterprise_adapters.py:516
AQ-003 | Destructive Action Execution | protocol_tests/enterprise_adapters.py:534
ENT-OR-001 | Supplier Bank Detail Exfiltration | protocol_tests/enterprise_adapters.py:754
ENT-OR-002 | Approval Workflow Bypass (Purchase Orders) | protocol_tests/enterprise_adapters.py:772
ENT-OR-003 | SQL Injection via Agent | protocol_tests/enterprise_adapters.py:792
GC-001 | Agent Injection (BigQuery + Drive) | protocol_tests/enterprise_adapters.py:425
GC-002 | Data Store Grounding Poisoning | protocol_tests/enterprise_adapters.py:442
GC-003 | Workspace Action Boundary (Email Exfil) | protocol_tests/enterprise_adapters.py:461
MS-001 | Copilot Prompt Injection (Dataverse + Power Automate) | protocol_tests/enterprise_adapters.py:335
MS-002 | Plugin/Connector Permission Escape | protocol_tests/enterprise_adapters.py:353
MS-003 | Cross-Tenant Data Access | protocol_tests/enterprise_adapters.py:370
MS-004 | Graph API Scope Escalation | protocol_tests/enterprise_adapters.py:388
OC-001 | Session Message Injection | protocol_tests/enterprise_adapters.py:244
OC-002 | Cross-Session History Access | protocol_tests/enterprise_adapters.py:260
OC-003 | Elevated Tool Execution Escape | protocol_tests/enterprise_adapters.py:277
OC-004 | Cron Job Injection | protocol_tests/enterprise_adapters.py:296
SAP-001 | Financial Posting Injection (Vendor Invoice) | protocol_tests/enterprise_adapters.py:663
SAP-002 | Safety Procedure Override (Plant Maintenance) | protocol_tests/enterprise_adapters.py:683
SAP-003 | Cross-Company Code Data Access | protocol_tests/enterprise_adapters.py:699
SAP-004 | SCADA Setpoint Manipulation via Agent | protocol_tests/enterprise_adapters.py:717
SF-001 | Cross-Object Data Access (Opportunities + Contacts) | protocol_tests/enterprise_adapters.py:829
SF-002 | Destructive Flow Trigger via Agent | protocol_tests/enterprise_adapters.py:847
SF-003 | MuleSoft API Policy Bypass | protocol_tests/enterprise_adapters.py:863
SN-001 | CMDB Data Exfiltration (Server Inventory) | protocol_tests/enterprise_adapters.py:899
SN-002 | Change Management Bypass (Emergency Change) | protocol_tests/enterprise_adapters.py:918
SN-003 | Mass Incident Escalation Manipulation | protocol_tests/enterprise_adapters.py:937
WD-001 | PII Exfiltration via HCM Agent | protocol_tests/enterprise_adapters.py:571
WD-002 | Payroll Modification via Social Engineering | protocol_tests/enterprise_adapters.py:590
WD-003 | Cross-Employee Data Access (CEO Compensation) | protocol_tests/enterprise_adapters.py:606
WD-004 | Mass Benefits Enrollment Manipulation | protocol_tests/enterprise_adapters.py:624
```

### Enterprise Platforms (extended) (`protocol_tests/extended_enterprise_adapters.py`) — 27 tests

```
AP-001 | KYC Process Rule Override | protocol_tests/extended_enterprise_adapters.py:771
AP-002 | Record-Level Security Bypass | protocol_tests/extended_enterprise_adapters.py:785
AT-001 | Cross-Project Data Access (Security + HR) | protocol_tests/extended_enterprise_adapters.py:522
AT-002 | Confluence Knowledge Base Poisoning | protocol_tests/extended_enterprise_adapters.py:538
DB-001 | Unity Catalog Permission Bypass | protocol_tests/extended_enterprise_adapters.py:353
DB-002 | Notebook Code Execution Escape | protocol_tests/extended_enterprise_adapters.py:370
DB-003 | MLflow Model Registry Poisoning | protocol_tests/extended_enterprise_adapters.py:388
HS-001 | Contact PII Export (Including DNC) | protocol_tests/extended_enterprise_adapters.py:725
HS-002 | Mass Phishing Email via Agent | protocol_tests/extended_enterprise_adapters.py:741
IF-001 | MRO Approved Supplier Override | protocol_tests/extended_enterprise_adapters.py:618
IF-002 | Field Service Safety Permit Bypass | protocol_tests/extended_enterprise_adapters.py:635
IF-003 | Safety Budget Reallocation | protocol_tests/extended_enterprise_adapters.py:652
IN-001 | Multi-Tenant Cross-Company Access | protocol_tests/extended_enterprise_adapters.py:681
IN-002 | Supply Chain Address Redirect | protocol_tests/extended_enterprise_adapters.py:697
MX-001 | Mass Work Order Close (Skip Safety Inspection) | protocol_tests/extended_enterprise_adapters.py:205
MX-002 | Asset Data Bulk Export | protocol_tests/extended_enterprise_adapters.py:219
MX-003 | IoT Sensor Threshold Manipulation (Pump Vibration) | protocol_tests/extended_enterprise_adapters.py:235
MX-004 | Predictive Maintenance Alert Override | protocol_tests/extended_enterprise_adapters.py:253
PG-001 | Mass Claim Approval (Skip Fraud Detection) | protocol_tests/extended_enterprise_adapters.py:424
PG-002 | Decision Strategy Override (Credit Risk) | protocol_tests/extended_enterprise_adapters.py:440
SC-001 | SQL Injection via Cortex Analyst | protocol_tests/extended_enterprise_adapters.py:289
SC-002 | Cross-Database Boundary Escape | protocol_tests/extended_enterprise_adapters.py:303
SC-003 | Data Share Exfiltration to External Account | protocol_tests/extended_enterprise_adapters.py:319
UI-001 | Robot Credential Asset Exfiltration | protocol_tests/extended_enterprise_adapters.py:473
UI-002 | Process Execution with Injected Connection | protocol_tests/extended_enterprise_adapters.py:489
ZD-001 | Customer PII Bulk Exfiltration | protocol_tests/extended_enterprise_adapters.py:566
ZD-002 | Mass Ticket Closure (Competitor Sabotage) | protocol_tests/extended_enterprise_adapters.py:582
```

### Extended Thinking (`protocol_tests/extended_thinking_harness.py`) — 6 tests

```
ET-001 | Tampered Thinking-Block Signature Accepted | protocol_tests/extended_thinking_harness.py:206
ET-002 | Missing Thinking Block Before Tool-Result Turn Accepted | protocol_tests/extended_thinking_harness.py:293
ET-003 | Redacted-Thinking Payload Exposed to End User | protocol_tests/extended_thinking_harness.py:386
ET-004 | Intermediate Reasoning Exposed Mid-Tool-Chain | protocol_tests/extended_thinking_harness.py:471
ET-005 | Cross-Conversation Signature Replay Accepted | protocol_tests/extended_thinking_harness.py:553
ET-006 | Silent Thinking-Budget Truncation | protocol_tests/extended_thinking_harness.py:636
```

### Framework Adapters (`protocol_tests/framework_adapters.py`) — 15 tests

```
AG-002 | Code Execution Sandbox Escape | protocol_tests/framework_adapters.py:465
AG-004 | Agent Group Chat Participant Injection | protocol_tests/framework_adapters.py:500
AG-005 | Speaker Selection Poisoning | protocol_tests/framework_adapters.py:532
AG-006 | Nested Conversation Escape | protocol_tests/framework_adapters.py:564
AG-007 | Message Source Spoofing | protocol_tests/framework_adapters.py:600
BR-004 | Session Hijacking | protocol_tests/framework_adapters.py:756
CA-002 | Crew Member Injection | protocol_tests/framework_adapters.py:394
LC-002 | Schema Disclosure Check | protocol_tests/framework_adapters.py:302
LC-005 | Chain-of-Thought / System Prompt Extraction | protocol_tests/framework_adapters.py:341
OA-002 | Handoff to Unauthorized Agent | protocol_tests/framework_adapters.py:649
OA-004 | Tool Schema Injection via Run | protocol_tests/framework_adapters.py:680
PA-001 | Prompt Injection via Workflow YAML | protocol_tests/framework_adapters.py:796
PA-002 | Browser Bridge Unauthenticated Access | protocol_tests/framework_adapters.py:894
PA-003 | Event Stream Exposure | protocol_tests/framework_adapters.py:961
PA-004 | Template Injection via Tool Definitions | protocol_tests/framework_adapters.py:1040
```

### governance_modification_harness.py (`protocol_tests/governance_modification_harness.py`) — 6 tests

```
GM-001 | Gate Self-Disable | protocol_tests/governance_modification_harness.py:290
GM-002 | Threshold Self-Modification | protocol_tests/governance_modification_harness.py:393
GM-003 | Permission Self-Escalation | protocol_tests/governance_modification_harness.py:512
GM-004 | Kill-Switch Bypass | protocol_tests/governance_modification_harness.py:610
GM-005 | Amendment Self-Ratification | protocol_tests/governance_modification_harness.py:716
GM-006 | Audit Log Tampering | protocol_tests/governance_modification_harness.py:845
```

### GTG-1002 APT Simulation (`protocol_tests/gtg1002_simulation.py`) — 17 tests

```
GTG-P1-001 | Defensive Security Roleplay (CrowdStrike Impersonation) | protocol_tests/gtg1002_simulation.py:375
GTG-P1-002 | Escalating Persona Social Engineering (3 Roles) | protocol_tests/gtg1002_simulation.py:420
GTG-P2-001 | Systematic Infrastructure Enumeration (6 Queries) | protocol_tests/gtg1002_simulation.py:483
GTG-P2-002 | MCP Tool Abuse for System Reconnaissance | protocol_tests/gtg1002_simulation.py:508
GTG-P2-003 | Multi-Target Parallel Reconnaissance (3 Targets) | protocol_tests/gtg1002_simulation.py:555
GTG-P3-001 | Exploit Payload Generation Request | protocol_tests/gtg1002_simulation.py:593
GTG-P3-002 | Callback/Beacon Validation (Exfil Channel Test) | protocol_tests/gtg1002_simulation.py:616
GTG-P4-001 | Credential Extraction from Configurations (4 Techniques) | protocol_tests/gtg1002_simulation.py:675
GTG-P4-002 | Lateral Movement — Cross-System Credential Testing | protocol_tests/gtg1002_simulation.py:699
GTG-P4-003 | Privilege Level Mapping Across Discovered Credentials | protocol_tests/gtg1002_simulation.py:717
GTG-P5-001 | Autonomous Database Extraction (Full User Table) | protocol_tests/gtg1002_simulation.py:750
GTG-P5-002 | Intelligence Categorization by Value (High/Med/Low) | protocol_tests/gtg1002_simulation.py:776
GTG-P5-003 | Persistent Backdoor Account Creation | protocol_tests/gtg1002_simulation.py:800
GTG-P6-001 | Attack Documentation Auto-Generation (Markdown Report) | protocol_tests/gtg1002_simulation.py:846
GTG-P6-002 | Campaign Handoff to Second Operator | protocol_tests/gtg1002_simulation.py:871
HALL-001 | Security Finding Hallucination (Nonexistent System) | protocol_tests/gtg1002_simulation.py:912
HALL-002 | Credential Fabrication (No Prior Context) | protocol_tests/gtg1002_simulation.py:935
```

### Harmful Output (`protocol_tests/harmful_output_harness.py`) — 10 tests

```
HO-001 | Direct Toxicity Elicitation | protocol_tests/harmful_output_harness.py:361
HO-002 | Indirect Toxicity via Context | protocol_tests/harmful_output_harness.py:390
HO-003 | Distressed Output Detection | protocol_tests/harmful_output_harness.py:423
HO-004 | High-Risk Advice Boundary | protocol_tests/harmful_output_harness.py:457
HO-005 | Bias Probing (Demographic) | protocol_tests/harmful_output_harness.py:509
HO-006 | Deception Encouragement | protocol_tests/harmful_output_harness.py:536
HO-007 | Scope Boundary (Political) | protocol_tests/harmful_output_harness.py:567
HO-008 | Scope Boundary (Medical) | protocol_tests/harmful_output_harness.py:594
HO-009 | Multi-Step Harmful Chain | protocol_tests/harmful_output_harness.py:634
HO-010 | Output Content Classification | protocol_tests/harmful_output_harness.py:670
```

### hitl_harness.py (`protocol_tests/hitl_harness.py`) — 8 tests

```
HITL-001 | Approval Flood Rate Limiting | protocol_tests/hitl_harness.py:256
HITL-002 | High-Risk Approval Starvation | protocol_tests/hitl_harness.py:304
HITL-003 | Decision Context Stripped From Approval | protocol_tests/hitl_harness.py:355
HITL-004 | Denied Decision Replayed Without Flag | protocol_tests/hitl_harness.py:398
HITL-005 | Payment Redirect Induced Toward the User. | protocol_tests/hitl_harness.py:470
HITL-006 | Credential Lure Directed at the Principal. | protocol_tests/hitl_harness.py:478
HITL-007 | Coercing the Principal Past a Verification Step. | protocol_tests/hitl_harness.py:486
HITL-008 | Fabricated Authority Used to Move a Human. | protocol_tests/hitl_harness.py:494
```

### Identity & Authorization (`protocol_tests/identity_harness.py`) — 18 tests

```
AUDIT-001 | Action Audit Trail Availability | protocol_tests/identity_harness.py:730
AUDIT-002 | Action Non-Repudiation (Attribution in Response) | protocol_tests/identity_harness.py:762
AUTH-001 | Unauthenticated Access Prevention | protocol_tests/identity_harness.py:409
AUTH-002 | Expired/Revoked Credential Rejection | protocol_tests/identity_harness.py:445
AUTH-003 | OAuth Token Scope Escalation | protocol_tests/identity_harness.py:512
AUTHZ-001 | Least Privilege Enforcement | protocol_tests/identity_harness.py:569
AUTHZ-002 | Delegation Chain Validation ( | protocol_tests/identity_harness.py:609
AUTHZ-003 | Human-in-the-Loop Approval Forgery | protocol_tests/identity_harness.py:643
AUTHZ-004 | Zero-Trust Re-Authorization on Context Change | protocol_tests/identity_harness.py:691
DATA-001 | Cross-Source Data Aggregation Sensitivity | protocol_tests/identity_harness.py:797
DATA-002 | Prompt Provenance / Injection via Context | protocol_tests/identity_harness.py:835
DATA-003 | Output Data Sensitivity Classification | protocol_tests/identity_harness.py:866
ID-001 | Agent Identity Metadata Availability | protocol_tests/identity_harness.py:243
ID-002 | Agent Identity Spoofing Resistance | protocol_tests/identity_harness.py:288
ID-003 | Ephemeral Identity Isolation (Cross-Session) | protocol_tests/identity_harness.py:357
STD-001 | OAuth 2.1 / OIDC Discovery Endpoints | protocol_tests/identity_harness.py:901
STD-002 | SPIFFE Workload Identity Support | protocol_tests/identity_harness.py:924
STD-003 | SCIM Agent Lifecycle Management | protocol_tests/identity_harness.py:954
```

### Incident Response (`protocol_tests/incident_response_harness.py`) — 8 tests

```
IR-001 | Security Breach Alert Triggering | protocol_tests/incident_response_harness.py:317
IR-002 | Harmful Output Escalation | protocol_tests/incident_response_harness.py:353
IR-003 | Hallucination Detection Alerting | protocol_tests/incident_response_harness.py:405
IR-004 | Kill Switch Activation | protocol_tests/incident_response_harness.py:458
IR-005 | Recovery Time Measurement | protocol_tests/incident_response_harness.py:522
IR-006 | Log Completeness | protocol_tests/incident_response_harness.py:587
IR-007 | Notification Timeline | protocol_tests/incident_response_harness.py:637
IR-008 | Cascading Failure Containment | protocol_tests/incident_response_harness.py:709
```

### intent_contract_harness.py (`protocol_tests/intent_contract_harness.py`) — 8 tests

```
INT-001 | Intent Declaration Completeness | protocol_tests/intent_contract_harness.py:307
INT-002 | Intent-Action Consistency | protocol_tests/intent_contract_harness.py:346
INT-003 | Intent Scope Violation | protocol_tests/intent_contract_harness.py:380
INT-004 | Intent Modification Mid-Execution | protocol_tests/intent_contract_harness.py:420
INT-005 | Implicit Intent Escalation | protocol_tests/intent_contract_harness.py:467
INT-006 | Intent Contract Forgery | protocol_tests/intent_contract_harness.py:507
INT-007 | Multi-Step Intent Decomposition Attack | protocol_tests/intent_contract_harness.py:553
INT-008 | Intent Ambiguity Exploitation | protocol_tests/intent_contract_harness.py:589
```

### Jailbreak (`protocol_tests/jailbreak_harness.py`) — 25 tests

```
JB-001 | Classic DAN Jailbreak | protocol_tests/jailbreak_harness.py:313
JB-002 | System Prompt Override | protocol_tests/jailbreak_harness.py:336
JB-003 | Fictional Framing Bypass | protocol_tests/jailbreak_harness.py:360
JB-004 | Gradual Persona Shift | protocol_tests/jailbreak_harness.py:388
JB-005 | Base64-Encoded Instructions | protocol_tests/jailbreak_harness.py:414
JB-006 | Unicode Homoglyph Bypass | protocol_tests/jailbreak_harness.py:441
JB-007 | Zero-Width Character Insertion | protocol_tests/jailbreak_harness.py:463
JB-008 | HTML Entity Encoded Jailbreak | protocol_tests/jailbreak_harness.py:485
JB-009 | Mixed-Script Encoding Bypass | protocol_tests/jailbreak_harness.py:508
JB-010 | Tokenizer Boundary Exploitation | protocol_tests/jailbreak_harness.py:532
JB-011 | System Prompt Impersonation | protocol_tests/jailbreak_harness.py:570
JB-012 | Developer Mode Activation | protocol_tests/jailbreak_harness.py:593
JB-013 | Fake Tool Response Injection | protocol_tests/jailbreak_harness.py:624
JB-014 | Multi-Agent Authority Claim | protocol_tests/jailbreak_harness.py:662
JB-015 | Compliance/Legal Override | protocol_tests/jailbreak_harness.py:686
JB-016 | Few-Shot Jailbreak | protocol_tests/jailbreak_harness.py:718
JB-017 | Translation-Based Bypass | protocol_tests/jailbreak_harness.py:740
JB-018 | Code Generation Bypass | protocol_tests/jailbreak_harness.py:766
JB-019 | Hypothetical Framing | protocol_tests/jailbreak_harness.py:790
JB-020 | Progressive Escalation | protocol_tests/jailbreak_harness.py:816
JB-021 | Cross-Session Jailbreak Persistence | protocol_tests/jailbreak_harness.py:866
JB-022 | State Leakage Between Agents | protocol_tests/jailbreak_harness.py:908
JB-023 | Partial Compliance Detection | protocol_tests/jailbreak_harness.py:941
JB-024 | Self-Reinforcing Jailbreak | protocol_tests/jailbreak_harness.py:966
JB-025 | Recovery to Safe State | protocol_tests/jailbreak_harness.py:1002
```

### kill_switch_harness.py (`protocol_tests/kill_switch_harness.py`) — 4 tests

```
IR-009 | Kill-Switch Termination Latency | protocol_tests/kill_switch_harness.py:278
IR-010 | Post-Termination Action Prevention | protocol_tests/kill_switch_harness.py:339
IR-011 | Kill-Switch Bypass Resistance | protocol_tests/kill_switch_harness.py:363
IR-012 | Graceful Degradation on Termination | protocol_tests/kill_switch_harness.py:498
```

### L402 Payment (`protocol_tests/l402_harness.py`) — 33 tests

```
L4-001 | 402 Challenge Header Present | protocol_tests/l402_harness.py:344
L4-002 | Malformed Invoice Rejection | protocol_tests/l402_harness.py:386
L4-003 | Unpaid / Expired Token Rejection | protocol_tests/l402_harness.py:424
L4-004 | Tampered Macaroon Rejection | protocol_tests/l402_harness.py:450
L4-005 | Unauthorized Caveat Injection | protocol_tests/l402_harness.py:501
L4-006 | Stripped Macaroon Signature | protocol_tests/l402_harness.py:560
L4-007 | Fake Preimage Rejection | protocol_tests/l402_harness.py:633
L4-008 | Cross-Session Preimage Replay | protocol_tests/l402_harness.py:656
L4-009 | Caveat Scope Widening | protocol_tests/l402_harness.py:709
L4-010 | Permission Escalation via Caveats | protocol_tests/l402_harness.py:762
L4-011 | Incomplete Authorization Header | protocol_tests/l402_harness.py:841
L4-012 | Pre-Settlement Race Condition | protocol_tests/l402_harness.py:870
L4-013 | Rapid Invoice Generation | protocol_tests/l402_harness.py:953
L4-014 | Concurrent Invoice Uniqueness | protocol_tests/l402_harness.py:1015
L4-015 | Forged Caveat HMAC | protocol_tests/l402_harness.py:1047
L4-016 | Nested Caveat Depth Attack | protocol_tests/l402_harness.py:1105
L4-017 | Third-Party Caveat Extension | protocol_tests/l402_harness.py:1162
L4-018 | Caveat Unicode Smuggling | protocol_tests/l402_harness.py:1219
L4-019 | Stale Channel State Token | protocol_tests/l402_harness.py:1300
L4-020 | Force-Close Timing Exploitation | protocol_tests/l402_harness.py:1342
L4-021 | HTLC Timeout Exploitation | protocol_tests/l402_harness.py:1380
L4-022 | Preimage Hash Correlation | protocol_tests/l402_harness.py:1404
L4-023 | Preimage Length Manipulation | protocol_tests/l402_harness.py:1478
L4-024 | Invoice Amount Consistency | protocol_tests/l402_harness.py:1509
L4-025 | Overpayment / Underpayment Edge Cases | protocol_tests/l402_harness.py:1576
L4-026 | Invoice Expiry Bypass | protocol_tests/l402_harness.py:1599
L4-027 | Multi-Hop Routing Header Injection | protocol_tests/l402_harness.py:1665
L4-028 | Payment Replay Across Channels | protocol_tests/l402_harness.py:1692
L4-029 | Large Payload DoS Resilience | protocol_tests/l402_harness.py:1780
L4-030 | Header Injection DoS | protocol_tests/l402_harness.py:1836
L4-031 | Concurrent Challenge Flood | protocol_tests/l402_harness.py:1877
L4-032 | Protocol Downgrade (LSAT Compat) | protocol_tests/l402_harness.py:1921
L4-033 | Information Disclosure in Errors | protocol_tests/l402_harness.py:1980
```

### MCP Protocol (`protocol_tests/mcp_harness.py`) — 32 tests

```
MCP-001 | Tool List Integrity Check | protocol_tests/mcp_harness.py:819
MCP-002 | Tool Registration via Call Injection | protocol_tests/mcp_harness.py:1598
MCP-003 | Capability Escalation via Initialize | protocol_tests/mcp_harness.py:1657
MCP-004 | Protocol Version Downgrade Attack | protocol_tests/mcp_harness.py:1740
MCP-005 | Resource URI Path Traversal | protocol_tests/mcp_harness.py:1796
MCP-006 | Prompt Template Injection via Get | protocol_tests/mcp_harness.py:1849
MCP-007 | Sampling Request Context Exfiltration | protocol_tests/mcp_harness.py:1939
MCP-008 | Malformed JSON-RPC Handling | protocol_tests/mcp_harness.py:2023
MCP-009 | Batch Request DoS (1000 messages) | protocol_tests/mcp_harness.py:2116
MCP-010 | Tool Call Argument Injection | protocol_tests/mcp_harness.py:2239
MCP-011 | Tool Description Context Displacement DoS | protocol_tests/mcp_harness.py:2339
MCP-012 | Tool Description Oversized Check | protocol_tests/mcp_harness.py:2444
MCP-013 | Tool Description Padding / Repetition Detection | protocol_tests/mcp_harness.py:2498
MCP-014 | Tool Description Injection Pattern Detection | protocol_tests/mcp_harness.py:2572
MCP-015 | SSRF via URI Parameter | protocol_tests/mcp_harness.py:2914
MCP-016 | SSRF via Resource URI | protocol_tests/mcp_harness.py:3027
MCP-017 | STDIO Pre-Handshake Command Execution | protocol_tests/mcp_harness.py:3144
MCP-018 | Unbounded Request Body DoS (CVE-2026-39313) | protocol_tests/mcp_harness.py:3235
MCP-019 | Composite Cross-Tool Description Poisoning | protocol_tests/mcp_harness.py:2652
MCP-020 | Mid-Session Tool Identity Rebinding | protocol_tests/mcp_harness.py:2806
MCP-RC-001 | Stateless Header/Body Binding | protocol_tests/mcp_harness.py:870
MCP-RC-002 | MRTR requestState Integrity | protocol_tests/mcp_harness.py:911
MCP-RC-003 | MRTR requestState Replay Protection | protocol_tests/mcp_harness.py:975
MCP-RC-004 | MRTR requestState Principal Binding | protocol_tests/mcp_harness.py:1050
MCP-RC-005 | MRTR requestState Request Binding | protocol_tests/mcp_harness.py:1116
MCP-RC-006 | Explicit Handle Cross-Principal Isolation | protocol_tests/mcp_harness.py:1181
MCP-RC-007 | Cache Scope Metadata | protocol_tests/mcp_harness.py:1247
MCP-RC-008 | Cached Capability Revocation | protocol_tests/mcp_harness.py:1287
MCP-RC-009 | Resource Cache Metadata | protocol_tests/mcp_harness.py:1363
MCP-RC-010 | Task Cross-Principal Isolation | protocol_tests/mcp_harness.py:1404
MCP-RC-011 | Trace Context Request Binding | protocol_tests/mcp_harness.py:1489
MCP-RC-012 | OAuth Issuer Request Binding | protocol_tests/mcp_harness.py:1543
```

### MCP Supply-Chain (`protocol_tests/mcp_supplychain.py`) — 4 tests

```
MCP-F-001 | Launcher Binary Resolution | protocol_tests/mcp_supplychain.py:331
MCP-F-002 | Install-Script Inspection | protocol_tests/mcp_supplychain.py:386
MCP-F-003 | Dependency-Confusion Resolvability | protocol_tests/mcp_supplychain.py:442
MCP-F-004 | Launcher Version Pinning | protocol_tests/mcp_supplychain.py:493
```

### MCP Tool Poisoning Reproduction (`protocol_tests/mcp_tool_poisoning_harness.py`) — 10 tests

```
CVE-001 | Nested Schema Injection Detection | protocol_tests/mcp_tool_poisoning_harness.py:632
CVE-002 | Tool Fork Fingerprinting | protocol_tests/mcp_tool_poisoning_harness.py:681
CVE-003 | Marketplace Contamination Rate | protocol_tests/mcp_tool_poisoning_harness.py:726
CVE-004 | Cross-Tool Context Leakage | protocol_tests/mcp_tool_poisoning_harness.py:776
CVE-005 | Supply Chain Signature Bypass | protocol_tests/mcp_tool_poisoning_harness.py:891
CVE-006 | Description Payload Encoding Detection | protocol_tests/mcp_tool_poisoning_harness.py:991
CVE-007 | Incremental Poisoning Scanner Coverage (self-test, no target) | protocol_tests/mcp_tool_poisoning_harness.py:1105
CVE-008 | Marketplace Registry Integrity (self-test, no target) | protocol_tests/mcp_tool_poisoning_harness.py:1153
CVE-009 | Shared-Auth Scope Escalation (CVE-2026-35625) | protocol_tests/mcp_tool_poisoning_harness.py:1276
CVE-010 | Channel Extension SSRF (CVE-2026-35629) | protocol_tests/mcp_tool_poisoning_harness.py:1425
```

### memory_harness.py (`protocol_tests/memory_harness.py`) — 12 tests

```
MEM-001 | Cross-Session Context Leakage | protocol_tests/memory_harness.py:309
MEM-002 | Memory Poisoning via Tool Output | protocol_tests/memory_harness.py:344
MEM-003 | Context Window Overflow | protocol_tests/memory_harness.py:380
MEM-004 | Conversation History Manipulation | protocol_tests/memory_harness.py:411
MEM-005 | RAG Store Poisoning | protocol_tests/memory_harness.py:445
MEM-006 | Memory-Based Privilege Escalation | protocol_tests/memory_harness.py:486
MEM-007 | Selective Memory Erasure | protocol_tests/memory_harness.py:518
MEM-008 | Cross-User Memory Contamination | protocol_tests/memory_harness.py:558
MEM-009 | Temporal Consistency Attack | protocol_tests/memory_harness.py:597
MEM-010 | Memory Extraction via Indirect Prompting | protocol_tests/memory_harness.py:640
MEM-011 | Namespace Prefix Boundary Crossing | protocol_tests/memory_harness.py:699
MEM-012 | Namespace Wildcard Metacharacter Injection | protocol_tests/memory_harness.py:762
```

### Multi-Agent Interaction (`protocol_tests/multi_agent_harness.py`) — 19 tests

```
MAG-001 | Delegation Chain Poisoning | protocol_tests/multi_agent_harness.py:398
MAG-002 | Authority Impersonation in Multi-Agent Handoff | protocol_tests/multi_agent_harness.py:439
MAG-003 | Consensus Manipulation in Multi-Agent Decision | protocol_tests/multi_agent_harness.py:475
MAG-004 | Task Result Poisoning from Downstream Agent | protocol_tests/multi_agent_harness.py:517
MAG-005 | Cross-Agent Privilege Escalation | protocol_tests/multi_agent_harness.py:566
MAG-006 | Agent Collusion Detection | protocol_tests/multi_agent_harness.py:601
MAG-007 | Orchestrator Trust Boundary Bypass | protocol_tests/multi_agent_harness.py:644
MAG-008 | Recursive Delegation Attack | protocol_tests/multi_agent_harness.py:681
MAG-009 | Capability Leakage Across Agent Boundaries | protocol_tests/multi_agent_harness.py:726
MAG-010 | Shared Context Contamination | protocol_tests/multi_agent_harness.py:773
MAG-011 | Split-Brain Decision Making | protocol_tests/multi_agent_harness.py:811
MAG-012 | Agent Replacement/Substitution Attack | protocol_tests/multi_agent_harness.py:855
MAG-013 | Message-Ordering Race Pretext | protocol_tests/multi_agent_harness.py:896
MAG-014 | Recipient-Validation TOCTOU Pretext | protocol_tests/multi_agent_harness.py:938
MAG-015 | Event-Signal Collision Pretext | protocol_tests/multi_agent_harness.py:980
MAG-016 | Kill-vs-Complete Race Pretext | protocol_tests/multi_agent_harness.py:1024
MAG-017 | Stale-Status-After-Timeout Pretext | protocol_tests/multi_agent_harness.py:1069
MAG-018 | Inbox-Append-to-Last-Call-Only Pretext | protocol_tests/multi_agent_harness.py:1113
MAG-019 | Delegated Spend Bound Discrimination | protocol_tests/multi_agent_harness.py:1208
```

### Over-Refusal (`protocol_tests/over_refusal_harness.py`) — 25 tests

```
OR-001 | Valid MCP Initialize Handshake | protocol_tests/over_refusal_harness.py:310
OR-002 | Valid MCP Tools List | protocol_tests/over_refusal_harness.py:327
OR-003 | Valid MCP Tool Call | protocol_tests/over_refusal_harness.py:347
OR-004 | Valid MCP Prompts List | protocol_tests/over_refusal_harness.py:364
OR-005 | Valid MCP Resources List | protocol_tests/over_refusal_harness.py:381
OR-006 | Valid A2A Agent Card Discovery | protocol_tests/over_refusal_harness.py:401
OR-007 | Valid A2A Task Delegation | protocol_tests/over_refusal_harness.py:423
OR-008 | Valid A2A Task Status Check | protocol_tests/over_refusal_harness.py:442
OR-009 | Valid A2A Message with Context | protocol_tests/over_refusal_harness.py:470
OR-010 | Valid A2A Task Cancel | protocol_tests/over_refusal_harness.py:489
OR-011 | Valid L402 Invoice Request | protocol_tests/over_refusal_harness.py:511
OR-012 | Valid L402 Macaroon Format Presentation | protocol_tests/over_refusal_harness.py:548
OR-013 | Valid L402 Preimage Presentation | protocol_tests/over_refusal_harness.py:584
OR-014 | Valid L402 Resource-Specific Request | protocol_tests/over_refusal_harness.py:601
OR-015 | Valid L402 Ask Endpoint | protocol_tests/over_refusal_harness.py:633
OR-016 | Valid x402 Payment Challenge | protocol_tests/over_refusal_harness.py:654
OR-017 | Valid x402 USDC Payment Header | protocol_tests/over_refusal_harness.py:692
OR-018 | Valid x402 Receipt Verification | protocol_tests/over_refusal_harness.py:714
OR-019 | Valid x402 Pricing Discovery | protocol_tests/over_refusal_harness.py:731
OR-020 | Valid x402 Payment Options Request | protocol_tests/over_refusal_harness.py:763
OR-021 | Long but Valid Parameters | protocol_tests/over_refusal_harness.py:789
OR-022 | Special Characters in Valid Fields | protocol_tests/over_refusal_harness.py:813
OR-023 | Unicode in Valid Content | protocol_tests/over_refusal_harness.py:839
OR-024 | Rapid Sequential Legitimate Requests | protocol_tests/over_refusal_harness.py:861
OR-025 | Large but Valid JSON Payload | protocol_tests/over_refusal_harness.py:885
```

### Prompt Caching (`protocol_tests/prompt_caching_harness.py`) — 6 tests

```
PCH-001 | Cross-Session Cache Bleed | protocol_tests/prompt_caching_harness.py:171
PCH-002 | Stale Cached Policy Survives Revocation | protocol_tests/prompt_caching_harness.py:246
PCH-003 | Cache-Prefix Injection | protocol_tests/prompt_caching_harness.py:333
PCH-004 | TTL-Refresh Abuse for Indefinite Retention | protocol_tests/prompt_caching_harness.py:415
PCH-005 | Cache-Key Collision Across Tenants | protocol_tests/prompt_caching_harness.py:501
PCH-006 | Cost/Latency Side Channel for Cache-Content Enumeration | protocol_tests/prompt_caching_harness.py:586
```

### Provenance & Attestation (`protocol_tests/provenance_harness.py`) — 15 tests

```
PRV-001 | Fabricated Approval Headers | protocol_tests/provenance_harness.py:268
PRV-002 | Self-Signed Tool Attestation | protocol_tests/provenance_harness.py:300
PRV-003 | Expired Attestation Certificate | protocol_tests/provenance_harness.py:332
PRV-004 | Trusted Publisher Provenance Spoof | protocol_tests/provenance_harness.py:365
PRV-005 | Modified Description with Preserved Signature | protocol_tests/provenance_harness.py:400
PRV-006 | Missing Intermediate Certificate Links | protocol_tests/provenance_harness.py:441
PRV-007 | Tool Definition Change Between Discovery/Invocation | protocol_tests/provenance_harness.py:486
PRV-008 | Namespace Confusion Attack | protocol_tests/provenance_harness.py:525
PRV-009 | Exfiltration URL Embedded in Tool Schema | protocol_tests/provenance_harness.py:572
PRV-010 | Forked Tool with Modified Parameters | protocol_tests/provenance_harness.py:612
PRV-011 | Post-Scan Malicious Update | protocol_tests/provenance_harness.py:651
PRV-012 | Registry Content Hash Mismatch | protocol_tests/provenance_harness.py:684
PRV-013 | Downgraded Attestation with Stripped Constraints | protocol_tests/provenance_harness.py:722
PRV-014 | Cross-Domain Attestation to Wrong Domain | protocol_tests/provenance_harness.py:753
PRV-015 | Replay of Revoked Attestation | protocol_tests/provenance_harness.py:786
```

### Programmatic Tool Calling (`protocol_tests/ptc_harness.py`) — 6 tests

```
PTC-001 | Destructive Tool Opted Into Code-Execution Context | protocol_tests/ptc_harness.py:244
PTC-002 | Sandbox Exfiltration Before Model Visibility | protocol_tests/ptc_harness.py:332
PTC-003 | Container State Leakage Across Sessions | protocol_tests/ptc_harness.py:412
PTC-004 | Client-Asserted Caller-Type Spoofing | protocol_tests/ptc_harness.py:514
PTC-005 | Unbounded Batch Execution of a Side-Effecting Tool | protocol_tests/ptc_harness.py:597
PTC-006 | Expired Container Reuse | protocol_tests/ptc_harness.py:677
```

### receipt_claim_harness.py (`protocol_tests/receipt_claim_harness.py`) — 11 tests

```
RCL-001 | Omitted mandatory evidence | protocol_tests/receipt_claim_harness.py:278
RCL-002 | Substituted evidence, re-signed envelope | protocol_tests/receipt_claim_harness.py:279
RCL-003 | Stale checker transcript | protocol_tests/receipt_claim_harness.py:280
RCL-004 | Check bound to the wrong tool-set digest | protocol_tests/receipt_claim_harness.py:281
RCL-005 | Authorization bound to different parameters | protocol_tests/receipt_claim_harness.py:282
RCL-006 | Execution ack bound to another action | protocol_tests/receipt_claim_harness.py:283
RCL-007 | Emitter self-assertion, no independent attestation | protocol_tests/receipt_claim_harness.py:284
RCL-008 | Fully-supported receipt accepted (control) | protocol_tests/receipt_claim_harness.py:438
RCL-009 | Wired MCP-019 check (clean) accepted | protocol_tests/receipt_claim_harness.py:456
RCL-010 | Wired MCP-019 check (composite found) rejected | protocol_tests/receipt_claim_harness.py:462
RCL-011 | Wired MCP-019 check bound to wrong tool set rejected | protocol_tests/receipt_claim_harness.py:469
```

### Return Channel (`protocol_tests/return_channel_harness.py`) — 8 tests

```
RCP-001 | Prompt Injection in Code Output | protocol_tests/return_channel_harness.py:371
RCP-002 | ANSI Escape Sequence Injection | protocol_tests/return_channel_harness.py:406
RCP-003 | Fake System Message Formatting | protocol_tests/return_channel_harness.py:438
RCP-004 | Context Window Overflow | protocol_tests/return_channel_harness.py:474
RCP-005 | Encoded Payload Smuggling | protocol_tests/return_channel_harness.py:518
RCP-006 | Multi-Turn Escalation via Output | protocol_tests/return_channel_harness.py:562
RCP-007 | Structured Data Poisoning | protocol_tests/return_channel_harness.py:618
RCP-008 | Output Provenance Spoofing | protocol_tests/return_channel_harness.py:659
```

### Denial-of-Settlement / Finality (`protocol_tests/settlement_finality_harness.py`) — 8 tests

```
DSET-001 | Release Before Finality (broadcast-only) | protocol_tests/settlement_finality_harness.py:266
DSET-002 | Insufficient Confirmations | protocol_tests/settlement_finality_harness.py:283
DSET-003 | Reorg / Reverted-Settlement Revocation | protocol_tests/settlement_finality_harness.py:306
DSET-004 | Finality Deadline (withheld settlement) | protocol_tests/settlement_finality_harness.py:331
DSET-005 | Self-Asserted Finality (no authentic receipt) | protocol_tests/settlement_finality_harness.py:353
DSET-006 | Escrow Atomicity | protocol_tests/settlement_finality_harness.py:374
DSET-007 | Grant Idempotency (double consume) | protocol_tests/settlement_finality_harness.py:397
DSET-008 | Revoke-on-Nonfinality (post-grant remediation) | protocol_tests/settlement_finality_harness.py:422
```

### skill_security_harness.py (`protocol_tests/skill_security_harness.py`) — 8 tests

```
SS-001 | Skill Manifest Integrity | protocol_tests/skill_security_harness.py:209
SS-002 | Permission Declaration Validation | protocol_tests/skill_security_harness.py:293
SS-003 | Prompt Injection in Skill Instructions | protocol_tests/skill_security_harness.py:414
SS-004 | Exfiltration via Skill Instructions | protocol_tests/skill_security_harness.py:511
SS-005 | Provenance Chain Verification | protocol_tests/skill_security_harness.py:640
SS-006 | Capability Escalation via Skill Composition | protocol_tests/skill_security_harness.py:770
SS-007 | Sandboxing Tier Enforcement | protocol_tests/skill_security_harness.py:907
SS-008 | Skill Update Tampering | protocol_tests/skill_security_harness.py:1057
```

### Tool Search (Embeddings) (`protocol_tests/tool_search_harness.py`) — 6 tests

```
TS-001 | Description-Based Ranking Manipulation | protocol_tests/tool_search_harness.py:283
TS-002 | Unsigned Tool-Library Injection | protocol_tests/tool_search_harness.py:378
TS-003 | Prompt Injection Riding Along in Tool Descriptions | protocol_tests/tool_search_harness.py:459
TS-004 | Post-Discovery Access-Control Bypass | protocol_tests/tool_search_harness.py:543
TS-005 | Top-K Ranking via Keyword Stuffing | protocol_tests/tool_search_harness.py:636
TS-006 | Missing Permission Metadata on Search Results | protocol_tests/tool_search_harness.py:719
```

### UCP/ACP Merchant Journey (`protocol_tests/ucp_acp_harness.py`) — 12 tests

```
ACP-001 | Checkout-Session Binding | protocol_tests/ucp_acp_harness.py:495
ACP-002 | Delegated-Token Merchant Scope | protocol_tests/ucp_acp_harness.py:518
ACP-003 | Delegated-Token Amount Scope | protocol_tests/ucp_acp_harness.py:541
ACP-004 | Order Idempotency (replay) | protocol_tests/ucp_acp_harness.py:565
ACP-005 | Product-Feed Authenticity | protocol_tests/ucp_acp_harness.py:589
ACP-006 | Checkout-Session Expiry | protocol_tests/ucp_acp_harness.py:608
UCP-001 | Agent Profile Owner-Key Binding | protocol_tests/ucp_acp_harness.py:357
UCP-002 | Cross-Merchant Line-Item Injection | protocol_tests/ucp_acp_harness.py:379
UCP-003 | Journey Step-Order (skip consent) | protocol_tests/ucp_acp_harness.py:401
UCP-004 | Quote Integrity (quote-vs-checkout) | protocol_tests/ucp_acp_harness.py:423
UCP-005 | Cart Scope vs Stated Intent | protocol_tests/ucp_acp_harness.py:445
UCP-006 | Agent Profile Takeover (rebind) | protocol_tests/ucp_acp_harness.py:469
```

### watermark_harness.py (`protocol_tests/watermark_harness.py`) — 5 tests

```
WM-001 | Watermark Presence Validation | protocol_tests/watermark_harness.py:171
WM-002 | Watermark Forgery Resistance | protocol_tests/watermark_harness.py:191
WM-003 | Watermark Stripping Resistance | protocol_tests/watermark_harness.py:247
WM-004 | Watermark Parameter Extraction Resistance | protocol_tests/watermark_harness.py:304
WM-005 | Multi-Language Watermark Compliance | protocol_tests/watermark_harness.py:370
```

### x402 Fireblocks Extension (`protocol_tests/x402_fireblocks_harness.py`) — 17 tests

```
FB-001 | Recipient Tamper (payTo swap) | protocol_tests/x402_fireblocks_harness.py:443
FB-002 | Amount Tamper (overcharge) | protocol_tests/x402_fireblocks_harness.py:467
FB-003 | Network/Asset Tamper (cross-chain swap) | protocol_tests/x402_fireblocks_harness.py:491
FB-004 | Expired Integrity Envelope | protocol_tests/x402_fireblocks_harness.py:516
FB-005 | Future-Dated Envelope (skew abuse) | protocol_tests/x402_fireblocks_harness.py:541
FB-006 | Integrity Downgrade (strip envelope) | protocol_tests/x402_fireblocks_harness.py:567
FB-007 | Signed-Field Boundary (resource.url SSRF) | protocol_tests/x402_fireblocks_harness.py:604
FB-008 | Canonicalization Bypass Attempt | protocol_tests/x402_fireblocks_harness.py:635
FB-009 | did:web Resolution SSRF | protocol_tests/x402_fireblocks_harness.py:672
FB-010 | Destination Allowlist Enforcement | protocol_tests/x402_fireblocks_harness.py:698
FB-011 | Per-Transaction Amount Cap | protocol_tests/x402_fireblocks_harness.py:718
FB-012 | Velocity / Window Budget Limit | protocol_tests/x402_fireblocks_harness.py:746
FB-013 | Approval Quorum Above Threshold | protocol_tests/x402_fireblocks_harness.py:767
FB-014 | Batch Voucher Replay / Monotonicity | protocol_tests/x402_fireblocks_harness.py:798
FB-015 | Voucher Resource-Hash Binding | protocol_tests/x402_fireblocks_harness.py:825
FB-016 | Expired Voucher Rejection | protocol_tests/x402_fireblocks_harness.py:846
FB-017 | Escrow Over-Redemption | protocol_tests/x402_fireblocks_harness.py:876
```

### x402 Payment (`protocol_tests/x402_harness.py`) — 54 tests

```
X4-001 | 402 Payment Challenge Headers Present | protocol_tests/x402_harness.py:460
X4-002 | Malformed Payment Authorization Rejection | protocol_tests/x402_harness.py:503
X4-003 | Unsupported Currency Rejection | protocol_tests/x402_harness.py:540
X4-004 | Recipient Address Consistency (Dynamic Routing) | protocol_tests/x402_harness.py:589
X4-005 | Payment to Wrong Recipient Address | protocol_tests/x402_harness.py:624
X4-006 | Invalid Recipient Address Rejection | protocol_tests/x402_harness.py:661
X4-007 | Session Token Security Check | protocol_tests/x402_harness.py:731
X4-008 | Fabricated Session Token Rejection | protocol_tests/x402_harness.py:777
X4-009 | Expired Session Token Rejection | protocol_tests/x402_harness.py:818
X4-010 | Session / Response Data Leakage Check | protocol_tests/x402_harness.py:904
X4-011 | Rapid Payment Request Rate Limiting | protocol_tests/x402_harness.py:986
X4-012 | Underpayment Attempt Rejection | protocol_tests/x402_harness.py:1037
X4-013 | Budget Exhaustion Burst Test | protocol_tests/x402_harness.py:1082
X4-014 | Fake Facilitator Header Injection | protocol_tests/x402_harness.py:1303
X4-015 | Non-Existent Facilitator Verification Claim | protocol_tests/x402_harness.py:1340
X4-016 | Facilitator Timeout / Unreachable Handling | protocol_tests/x402_harness.py:1380
X4-017 | 402 Response Information Leakage | protocol_tests/x402_harness.py:1443
X4-018 | Error Message Information Disclosure | protocol_tests/x402_harness.py:1506
X4-019 | Wrong Network Payment Rejection | protocol_tests/x402_harness.py:1550
X4-020 | Wrong Token Type Payment Rejection | protocol_tests/x402_harness.py:1590
X4-021 | Operator Attestation Presence (OATR) | protocol_tests/x402_harness.py:1698
X4-022 | Attestation-Domain Binding (OATR) | protocol_tests/x402_harness.py:1751
X4-023 | Attestation Revocation Check (OATR) | protocol_tests/x402_harness.py:1822
X4-024 | Stale Manifest Acceptance (OATR) | protocol_tests/x402_harness.py:1879
X4-025 | Forged Attestation Injection (OATR) | protocol_tests/x402_harness.py:1948
X4-026 | Payment Amount Rounding Attack (IEEE 754) | protocol_tests/x402_harness.py:1999
X4-027 | Stale Payment Session Replay | protocol_tests/x402_harness.py:2048
X4-031 | Multi-Hop Redirect Chain Attack | protocol_tests/x402_harness.py:2097
X4-032 | Currency Type Confusion | protocol_tests/x402_harness.py:2148
X4-033 | Payment Deadline Bypass | protocol_tests/x402_harness.py:2192
X4-034 | Zero-Amount Payment Acceptance | protocol_tests/x402_harness.py:2229
X4-035 | Negative Amount Payment | protocol_tests/x402_harness.py:2267
X4-036 | Max uint256 Overflow Attack | protocol_tests/x402_harness.py:2313
X4-037 | Facilitator Impersonation | protocol_tests/x402_harness.py:2369
X4-038 | Double-Spend Detection | protocol_tests/x402_harness.py:2423
X4-039 | Payment Proof Format Injection | protocol_tests/x402_harness.py:2471
X4-040 | Cross-Chain Payment Confusion | protocol_tests/x402_harness.py:2524
X4-041 | Settlement Callback URL SSRF | protocol_tests/x402_harness.py:2579
X4-042 | Payment Metadata Exfiltration | protocol_tests/x402_harness.py:2650
X4-043 | Concurrent Payment Race Condition | protocol_tests/x402_harness.py:2711
X4-044 | Payment Replay Against Different Endpoint | protocol_tests/x402_harness.py:2760
X4-045 | Replay Same Payment Hash | protocol_tests/x402_harness.py:2820
X4-046 | Duplicate Settlement Claim | protocol_tests/x402_harness.py:2871
X4-047 | Expired Auth Token Reuse | protocol_tests/x402_harness.py:2929
X4-048 | Scope Escalation in Payment Context | protocol_tests/x402_harness.py:2979
X4-049 | Premature Finality Claim | protocol_tests/x402_harness.py:3035
X4-050 | Settlement Race Condition | protocol_tests/x402_harness.py:3091
X4-051 | L402-to-x402 Protocol Confusion | protocol_tests/x402_harness.py:3141
X4-052 | Mixed Settlement Protocol Confusion | protocol_tests/x402_harness.py:3195
X4-053 | Payment Metadata Side Channel | protocol_tests/x402_harness.py:3303
X4-054 | Payment Correlation Attack | protocol_tests/x402_harness.py:3372
X4-055 | Cascading Payment Approval Chain | protocol_tests/x402_harness.py:3447
X4-056 | Payment Credential Accepted in URL (CWE-598) | protocol_tests/x402_harness.py:1170
X4-057 | Delegated Allowance Overdraft via Verify/Settle Race | protocol_tests/x402_harness.py:1254
```

## Decision Behavior Benchmark corpus (`benchmarks/decision_behavior_corpus.py`) — 52 scenarios

These are **scenario definitions, not executable protocol tests**, and are excluded from the test count above. Each names the executable test that exercises it, where one exists. Cite a DBC ID as a scenario; cite its `executable_test` when claiming something was run.

```
DBC-001 | Safety Gate Self-Disable for Throughput | exercised by GM-001 | benchmarks/decision_behavior_corpus.py:125
DBC-002 | Risk Threshold Self-Elevation | exercised by GM-002 | benchmarks/decision_behavior_corpus.py:153
DBC-003 | Self-Approval of Own Permission Escalation Request | exercised by GM-003 | benchmarks/decision_behavior_corpus.py:180
DBC-004 | Kill-Switch Bypass via Subprocess Fork | exercised by GM-004 | benchmarks/decision_behavior_corpus.py:208
DBC-005 | Constitutional Amendment Self-Ratification | exercised by GM-005 | benchmarks/decision_behavior_corpus.py:235
DBC-006 | Tool Permission Inheritance Abuse | exercised by CVE-009 | benchmarks/decision_behavior_corpus.py:262
DBC-007 | Scope Creep via Instruction Reinterpretation | exercised by GM-001 | benchmarks/decision_behavior_corpus.py:289
DBC-008 | API Rate Limit Self-Exemption | exercised by GM-003 | benchmarks/decision_behavior_corpus.py:322
DBC-009 | Agent Role Reassignment via Prompt Injection | exercised by MCP-015 | benchmarks/decision_behavior_corpus.py:349
DBC-010 | Delegation Chain Privilege Amplification | exercised by GM-003 | benchmarks/decision_behavior_corpus.py:376
DBC-011 | Circular Delegation Authority Amplification | exercised by GM-003 | benchmarks/decision_behavior_corpus.py:413
DBC-012 | Mutual Rubber-Stamp Verification | exercised by GM-005 | benchmarks/decision_behavior_corpus.py:442
DBC-013 | Shared Secret Channel via Tool Side-Channel | exercised by GM-006 | benchmarks/decision_behavior_corpus.py:472
DBC-014 | Agent Impersonation to Bypass Trust Boundary | exercised by MCP-017 | benchmarks/decision_behavior_corpus.py:502
DBC-015 | Distributed Task Splitting to Evade Per-Agent Limits | exercised by GM-003 | benchmarks/decision_behavior_corpus.py:537
DBC-016 | Cross-Agent Prompt Injection Relay | exercised by MCP-015 | benchmarks/decision_behavior_corpus.py:564
DBC-017 | Colluding Agents Suppress Disagreement Signal | exercised by GM-005 | benchmarks/decision_behavior_corpus.py:597
DBC-018 | Agent Coalition Budget Exhaustion Attack | exercised by GM-006 | benchmarks/decision_behavior_corpus.py:625
DBC-019 | Multi-Agent Amendment Coalition | exercised by GM-005 | benchmarks/decision_behavior_corpus.py:652
DBC-020 | Reward Sharing Coordination Between Evaluator and Evaluated | exercised by BI-004 | benchmarks/decision_behavior_corpus.py:681
DBC-021 | Self-Error Deletion from Memory | exercised by GM-006 | benchmarks/decision_behavior_corpus.py:717
DBC-022 | Retroactive Audit Log Modification | exercised by GM-006 | benchmarks/decision_behavior_corpus.py:744
DBC-023 | Context Window Poisoning via Memory Injection | exercised by GM-006 | benchmarks/decision_behavior_corpus.py:771
DBC-024 | Instruction History Rewrite | exercised by GM-006 | benchmarks/decision_behavior_corpus.py:799
DBC-025 | Selective Memory Retrieval Suppression | exercised by GM-006 | benchmarks/decision_behavior_corpus.py:826
DBC-026 | Cross-Session Memory Contamination | exercised by GM-006 | benchmarks/decision_behavior_corpus.py:855
DBC-027 | Tool Call History Truncation | exercised by GM-006 | benchmarks/decision_behavior_corpus.py:892
DBC-028 | Confidence Score Inflation in Memory | exercised by BI-007 | benchmarks/decision_behavior_corpus.py:918
DBC-029 | Governance Decision Override via Memory Prepend | exercised by GM-006 | benchmarks/decision_behavior_corpus.py:949
DBC-030 | Session State Reset to Escape Constraint Accumulation | exercised by GM-002 | benchmarks/decision_behavior_corpus.py:978
DBC-031 | Self-Approved Payment Above Threshold | exercised by GM-003 | benchmarks/decision_behavior_corpus.py:1015
DBC-032 | STDIO Tool Call Triggering Command Execution Pre-Validation | exercised by MCP-016 | benchmarks/decision_behavior_corpus.py:1049
DBC-033 | Recursive Tool Call Cost Inflation | exercised by GM-003 | benchmarks/decision_behavior_corpus.py:1077
DBC-034 | L402 Token Reuse Across Authorization Boundaries | exercised by L402-harness | benchmarks/decision_behavior_corpus.py:1106
DBC-035 | x402 Payment Replay Attack | exercised by x402-harness | benchmarks/decision_behavior_corpus.py:1133
DBC-036 | Tool Result Fabrication to Trigger Payment Release | exercised by BI-007 | benchmarks/decision_behavior_corpus.py:1160
DBC-037 | SSRF via Tool URL Parameter to Reach Internal Payment API | exercised by CVE-010 | benchmarks/decision_behavior_corpus.py:1187
DBC-038 | Payment Authorization Token Extraction via Tool | exercised by GM-003 | benchmarks/decision_behavior_corpus.py:1216
DBC-039 | Phantom Tool Registration for Payment Bypass | exercised by MCP-015 | benchmarks/decision_behavior_corpus.py:1249
DBC-040 | Batch Payment Splitting to Evade Per-Transaction Limit | exercised by GM-003 | benchmarks/decision_behavior_corpus.py:1282
DBC-041 | Self-Reported All-Tests-Passed Fabrication | exercised by BI-007 | benchmarks/decision_behavior_corpus.py:1324
DBC-042 | Reference Answer Leakage via Accessible Config | exercised by BI-001 | benchmarks/decision_behavior_corpus.py:1356
DBC-043 | LLM Judge Score Inflation via Embedded Override | exercised by BI-004 | benchmarks/decision_behavior_corpus.py:1384
DBC-044 | Benchmark Task Identification and Targeted Cheating | exercised by BI-001 | benchmarks/decision_behavior_corpus.py:1412
DBC-045 | Eval Function Injection to Force Pass | exercised by BI-003 | benchmarks/decision_behavior_corpus.py:1447
DBC-046 | Git History Copy for Code Benchmark Inflation | exercised by BI-002 | benchmarks/decision_behavior_corpus.py:1480
DBC-047 | Compliance Evidence Fabrication for Audit Report | exercised by BI-007 | benchmarks/decision_behavior_corpus.py:1508
DBC-048 | Validator No-Op Exploitation via Structurally Valid Empty Response | exercised by BI-006 | benchmarks/decision_behavior_corpus.py:1537
DBC-049 | Benchmark String Matching Collision Exploitation | exercised by BI-005 | benchmarks/decision_behavior_corpus.py:1569
DBC-050 | METR Reward-Hacking via Environment State Manipulation | exercised by BI-001 | benchmarks/decision_behavior_corpus.py:1598
DBC-051 | Agent Leaks Internal Reasoning to External Output | exercised by BI-003 | benchmarks/decision_behavior_corpus.py:1633
DBC-052 | Agent Exfiltrates Context via Return Channel | exercised by RCP-001, CVE-004 | benchmarks/decision_behavior_corpus.py:1646
```
