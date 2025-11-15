# 🔥 Red Team / Blue Team Test Specification
## MuleSoft Agent Fabric - Complete Testing Package

**Version**: 2.0 (InfraGard Enhanced)
**Date**: November 15, 2025
**Status**: ✅ PRODUCTION READY

---

## 📋 Package Contents

This comprehensive testing package includes all deliverables for Red Team/Blue Team validation of the MuleSoft Agent Fabric deployment.

### Core Documents

1. **[agent-fabric-red-blue-team-spec.md](agent-fabric-red-blue-team-spec.md)**
   - Original Red Team/Blue Team specification
   - 20 test scenarios across STRIDE threat model
   - Architecture overview and threat model

2. **[ENHANCED-RED-BLUE-TEAM-TEST-PLAN.md](ENHANCED-RED-BLUE-TEAM-TEST-PLAN.md)** ⭐ **PRIMARY DOCUMENT**
   - **Version 2.0** - Integrates InfraGard November 2025 guidance
   - **27 test scenarios** (20 original + 7 InfraGard-derived)
   - Phased deployment methodology (Lab → HiL → Shadow → Limited → Full)
   - Human-in-loop requirements for safety-critical decisions
   - 90-day implementation roadmap
   - NIST AI RMF, OWASP LLM Top 10, ISA/IEC 62443 framework alignment

### Executive Materials

3. **[EXECUTIVE-PRESENTATION.md](EXECUTIVE-PRESENTATION.md)**
   - 24-slide executive stakeholder briefing
   - ROI analysis: $292K investment → $42M+ value (9,000% ROI)
   - Decision framework for GO/NO-GO approval
   - Risk mitigation and success criteria
   - **Convert to PowerPoint** using Pandoc or copy/paste into slides

### Operational Playbooks

4. **[BLUE-TEAM-PLAYBOOKS.md](BLUE-TEAM-PLAYBOOKS.md)**
   - Complete incident response playbooks for all 27 scenarios
   - Detection → Analysis → Response → Recovery workflows
   - Escalation matrix with contact lists
   - Post-incident review templates
   - Quick reference cards

### Automation & Testing

5. **[red_team_automation.py](red_team_automation.py)**
   - Complete Python test automation suite
   - All 27 test scenarios automated
   - InfraGard threat intelligence integration
   - JSON report generation with NIST/OWASP mapping
   - **Run with**: `python red_team_automation.py`

### Monitoring & Dashboards

6. **[grafana-dashboards.json](grafana-dashboards.json)**
   - 3 pre-configured Grafana dashboards:
     - Executive Security & Safety Dashboard
     - Process Safety Management Dashboard (Operations)
     - Red Team Testing Dashboard
   - Prometheus and Elasticsearch queries
   - Alerting rules with PagerDuty/Slack integration
   - **Import into Grafana** via UI

---

## 🎯 Quick Start Guide

### Step 1: Review the Enhanced Test Plan
```bash
# Read the primary document
cat ENHANCED-RED-BLUE-TEAM-TEST-PLAN.md
```

**Key Sections**:
- Section 3: Phased Testing Approach (5 phases over 12 weeks)
- Section 4: 27 Test Scenarios (detailed attack vectors)
- Section 5: Blue Team Detection Framework
- Section 7: 90-Day Implementation Roadmap

### Step 2: Present to Executive Stakeholders
```bash
# Review executive presentation
cat EXECUTIVE-PRESENTATION.md

# Convert to PowerPoint (requires Pandoc)
pandoc EXECUTIVE-PRESENTATION.md -o executive-presentation.pptx \
  --reference-doc=template.pptx
```

**Decision Required**: $292K budget approval for 12-week testing program

### Step 3: Set Up Test Environment
```bash
# Install Python dependencies
pip install requests geopy

# Configure CloudHub endpoints (already in script)
# - Application 1: agentic-orchestration-mule
# - Application 2: turnaround-management-agents
# - Application 3: order-to-cash-agents
# - Broker: agentic-broker-runtime
# - MCP Servers: safety, context, document
```

### Step 4: Run Automated Tests
```bash
# Execute all 27 test scenarios
python red_team_automation.py

# Output:
# - Console: Real-time test execution
# - red_team_report_YYYYMMDD_HHMMSS.json: Detailed results
# - red_team_tests.log: Execution log
```

**Expected Runtime**: ~10-15 minutes (depends on rate limiting)

### Step 5: Deploy Monitoring Dashboards
```bash
# Import Grafana dashboards
curl -X POST http://grafana:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${GRAFANA_API_KEY}" \
  -d @grafana-dashboards.json
```

Access dashboards at:
- `http://grafana:3000/d/agent-fabric-exec` - Executive View
- `http://grafana:3000/d/agent-fabric-safety` - Safety View
- `http://grafana:3000/d/red-team-testing` - Testing View

### Step 6: Follow Blue Team Playbooks
```bash
# Review incident response procedures
cat BLUE-TEAM-PLAYBOOKS.md

# Example: Rogue agent detected
# 1. Follow RT-001 playbook
# 2. Execute containment steps
# 3. Document in post-incident template
```

---

## 📊 Test Scenarios Overview

### Original 20 Scenarios (Base Spec)

#### SPOOFING (3)
- RT-001: Rogue agent registration
- RT-014: Rogue orchestration join
- RT-020: MCP replay attack

#### TAMPERING (11)
- RT-003: SAP prompt injection
- RT-004: SCADA sensor poisoning
- RT-005: Multi-agent cascade corruption
- RT-009: Long-context corruption
- RT-010: Maintenance fraud
- RT-013: SAP → SNOW contamination
- RT-015: IoT → SAP mismatch
- RT-016: Drift via edge cases
- RT-017: SCADA shutdown suggestion
- RT-018: Social engineering the agent
- RT-019: Priority inflation

#### INFORMATION DISCLOSURE (1)
- RT-007: Unauthorized financial data access

#### DENIAL OF SERVICE (2)
- RT-008: Orchestration flood
- RT-012: A2A recursion loop

#### ELEVATION OF PRIVILEGE (3)
- RT-002: Unauthorized A2A escalation
- RT-006: Tool overreach attempt
- RT-011: Safety override attempt

### NEW: InfraGard-Derived Scenarios (7)

#### RT-021: Polymorphic Attack (IT Threat)
**Source**: Andrew's presentation on adversarial attacks
**Method**: AI-generated attack variations bypass pattern detection
**Defense**: Behavior-based detection, not signatures

#### RT-022: LLM Hallucination Injection (OWASP LLM01)
**Source**: OWASP Top 10 for LLMs
**Method**: Cause AI to generate false safety procedures
**Defense**: MCP Safety Server cross-validation

#### RT-023: Data Poisoning via MCP Context (OWASP LLM03)
**Source**: Integrity attacks discussion
**Method**: Corrupt AI training data or context
**Defense**: Cryptographic hashing, immutable logs

#### RT-024: Normalization of Deviance Attack (OT Threat)
**Source**: Marco Ayala's warning about OT drift
**Method**: Gradually shift safety baselines to unsafe levels
**Defense**: Drift detection, periodic baseline reset

#### RT-025: Superman Effect Credential Theft (IT Threat)
**Source**: Andrew's incident triage example
**Method**: Geo-location velocity attack (Houston → Tokyo in 15 min)
**Defense**: Geo-location validation, velocity checks

#### RT-026: Black Box Vendor System Attack (OT Concern)
**Source**: Marco's concern about opaque vendor systems
**Method**: Vendor system makes unsafe recommendations
**Defense**: Output validation, vendor SLA enforcement

#### RT-027: Emergency Shutdown Manipulation (Process Safety)
**Source**: Process safety management focus
**Method**: Prevent emergency shutdown during actual emergency
**Defense**: Redundant safety systems, bypass detection

---

## 🔑 Key Insights from InfraGard Session

### Marco Ayala (National Energy Sector Chief, InfraGard)

> **"Skip stage gates at your peril - OT failures have consequences IT teams rarely face"**

**Implication**: Must follow phased deployment (Lab → HiL → Shadow → Limited → Full)

> **"Human in the loop is MANDATORY for safety-critical systems"**

**Implication**: AI recommends, humans decide on safety-critical decisions

> **"Normalization of deviance - when nothing bad happens, we accept it as new normal"**

**Implication**: Implement drift detection and periodic baseline resets

### Andrew (IT Section Lead, InfraGard)

> **"Polymorphic attacks designed to bypass pattern detection"**

**Implication**: Use behavior-based detection, not signature-based

> **"Superman effect - logged in Houston, 15 min later in Tokyo"**

**Implication**: Geo-location validation for credential theft detection

---

## 📈 Success Criteria

### Security Metrics (IT Focus)

| Metric | Target | Measurement |
|--------|--------|-------------|
| Detection Latency (TTD) | < 3s | SIEM timestamp analysis |
| Block Accuracy | ≥ 99% | True Positives / Total Attacks |
| False Positive Rate | < 3% | False Positives / Total Requests |
| Lineage Traceability | 100% | A2A chains with correlation IDs |
| Recovery Time (TTC) | < 60s | Detection to safe state |

### Safety Metrics (OT Focus)

| Metric | Target | Measurement |
|--------|--------|-------------|
| Safety Incidents | 0 | Incidents attributable to AI |
| Unsafe Recommendations Blocked | 100% | Blocked / Total Unsafe |
| Human Approval Compliance | 100% | Required approvals obtained |
| Kill-Switch Activation Time | < 1s | From violation to safe state |
| MCP Safety Validation | 100% | Procedures cross-checked |
| Normalization Drift Detection | < 5% | Baseline vs current variance |

---

## 🛠️ Framework Alignment

### NIST AI Risk Management Framework
✅ **GOVERN**: Executive ownership, risk categorization
✅ **MAP**: Use case mapping, threat modeling (STRIDE)
✅ **MEASURE**: Drift detection, performance metrics, TTD/TTC
✅ **MANAGE**: Human oversight, incident response, kill-switch

### OWASP Top 10 for LLMs
✅ **LLM01**: Prompt Injection → RT-003, RT-018, RT-022
✅ **LLM02**: Insecure Output Handling → RT-017
✅ **LLM03**: Training Data Poisoning → RT-023
✅ **LLM04**: Model Denial of Service → RT-008, RT-009
✅ **LLM06**: Sensitive Information Disclosure → RT-007
✅ **LLM08**: Excessive Agency → RT-002, RT-006, RT-011

### ISA/IEC 62443 (Industrial Control Systems)
✅ **Security Level 1**: Basic protection (all agents)
✅ **Security Level 2**: Intentional violation protection (all agents)
✅ **Security Level 3**: Sophisticated means protection (critical agents)
✅ **Security Level 4**: Air-gapped fallback (safety-critical only)

---

## 📞 Support & Contact

### InfraGard Resources
- **InfraGard Portal**: https://www.infragard.org/
- **Houston AI-CSC Meetings**: Second Tuesday of each month
- **Threat Intelligence**: Access via member portal

### Framework References
- **NIST AI RMF**: https://www.nist.gov/itl/ai-risk-management-framework
- **OWASP LLM Top 10**: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- **ISA/IEC 62443**: Industrial automation and control systems security
- **CISA AI Guidance**: https://www.cisa.gov/topics/emerging-technologies/artificial-intelligence

### Project Team
- **Executive Sponsor**: [CISO/CIO Name]
- **Red Team Lead**: [Name]
- **Blue Team Lead**: [Name]
- **OT Lead**: [Process Safety Engineer]
- **IT Lead**: [Security Architect]

---

## 📝 Usage Instructions

### For Security Teams
1. Review [ENHANCED-RED-BLUE-TEAM-TEST-PLAN.md](ENHANCED-RED-BLUE-TEAM-TEST-PLAN.md)
2. Run automated tests: `python red_team_automation.py`
3. Follow [BLUE-TEAM-PLAYBOOKS.md](BLUE-TEAM-PLAYBOOKS.md) for incident response
4. Monitor via Grafana dashboards

### For Executive Stakeholders
1. Review [EXECUTIVE-PRESENTATION.md](EXECUTIVE-PRESENTATION.md)
2. Approve $292K budget for 12-week program
3. Assign executive sponsor (CISO/CIO)
4. Review monthly progress via executive dashboard

### For Operations Teams
1. Review phased deployment approach (Section 3 of enhanced plan)
2. Participate in cross-functional working group
3. Monitor Process Safety Management dashboard
4. Validate human-in-loop workflows

### For Compliance/Legal
1. Review framework alignment (NIST, OWASP, ISA)
2. Validate regulatory compliance requirements
3. Review incident response procedures
4. Sign off on GO/NO-GO criteria

---

## 🚀 Next Steps

### Immediate (This Week)
- [ ] Executive approval for budget ($292K)
- [ ] Assign executive sponsor (CISO/CIO)
- [ ] Form cross-functional working group
- [ ] All team members join InfraGard

### Week 1-2 (Foundation)
- [ ] Deploy lab environment
- [ ] Baseline current security posture
- [ ] Install monitoring tools (Grafana, Splunk/ELK)
- [ ] Document test plan

### Week 3-12 (Execution)
- [ ] Phase 2: Hardware in Loop testing
- [ ] Phase 3: Shadow mode deployment
- [ ] Phase 4: Limited production
- [ ] Phase 5: Full deployment decision (GO/NO-GO)

### Day 90 (Decision Point)
- [ ] Review success criteria validation
- [ ] Executive GO/NO-GO decision
- [ ] If GO: Proceed to full deployment
- [ ] If NO-GO: Return to shadow mode, address gaps

---

## 📚 Additional Resources

### InfraGard November 2025 Session
- **Presenters**: Marco Ayala, Andrew
- **Topic**: AI in Critical Infrastructure (OT) and Information Technology (IT)
- **Key Takeaways**: Phased deployment, human-in-loop, normalization of deviance

### MuleSoft Repository
- **URL**: https://github.com/msaleme/MuleSoft-Agentic-Fabric-Demo
- **Applications**: 3 CloudHub deployments (13 agents + 3 MCP servers)
- **Documentation**: Complete setup and configuration guides

---

## ⚖️ License & Acknowledgments

**Status**: Private - All Rights Reserved

**Acknowledgments**:
- **InfraGard Houston**: AI-CSC Monthly Meeting guidance
- **Marco Ayala**: National Energy Sector Chief, process safety insights
- **Andrew**: IT Section Lead, polymorphic attack awareness
- **MuleSoft**: Agent Fabric platform, A2A protocol, MCP integration
- **NIST, OWASP, ISA**: Framework guidance and standards

---

## 📄 Document Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-11-01 | Initial Red Team/Blue Team spec (20 scenarios) |
| 2.0 | 2025-11-15 | InfraGard integration (27 scenarios, phased deployment, human-in-loop) |

---

**Status**: ✅ PRODUCTION READY
**Last Updated**: November 15, 2025
**Contact**: [Security Team Email]

---

**End of README**
