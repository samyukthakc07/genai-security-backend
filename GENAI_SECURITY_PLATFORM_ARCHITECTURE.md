# GenAI Security Platform
## OWASP GenAI Security Management — Complete Architecture

> **Platform:** GenAI Security Platform (Django REST + React Frontend)
> **Framework:** OWASP LLM Top 10 Security Management
> **Date:** June 2026

---

# TABLE OF CONTENTS

1. [System Architecture](#1-system-architecture)
2. [Folder Structure](#2-folder-structure)
3. [Database Schema](#3-database-schema)
4. [API Design](#4-api-design)
5. [Dashboard Design](#5-dashboard-design)
6. [Sidebar Menu Structure](#6-sidebar-menu-structure)
7. [Backend Models Detail](#7-backend-models-detail)
8. [Security Scan Workflow](#8-security-scan-workflow)
9. [AI Security Engine Design](#9-ai-security-engine-design)
10. [Frontend Component Architecture](#10-frontend-component-architecture)
11. [Step-by-Step Implementation Roadmap](#11-step-by-step-implementation-roadmap)

---

# 1. SYSTEM ARCHITECTURE

## 1.1 High-Level Architecture (Converted from ASM)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        QUANTUMSEC AI SHIELD                          │
│                    GenAI Security Management Platform                  │
└─────────────────────────────────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
┌───────────────────┐    ┌───────────────────┐    ┌───────────────────┐
│   FRONTEND LAYER  │    │   API GATEWAY     │    │   AUTH LAYER      │
│  (React/Angular)  │◄──►│  (Django REST)    │◄──►│  (JWT + RBAC)     │
│                   │    │                   │    │                   │
│  - Dashboard      │    │  - REST APIs      │    │  - Organizations  │
│  - Scan Modules   │    │  - WebSockets     │    │  - Projects       │
│  - Reports        │    │  - Rate Limiting  │    │  - Roles/Perms    │
│  - Compliance     │    │  - Caching        │    │  - SSO            │
└───────────────────┘    └────────┬──────────┘    └───────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │     SERVICE LAYER        │
                    │  (Core Business Logic)   │
                    │                          │
                    │  ┌────────────────────┐  │
                    │  │  Scan Orchestrator │  │
                    │  └────────────────────┘  │
                    │  ┌────────────────────┐  │
                    │  │  Detection Engine  │  │
                    │  └────────────────────┘  │
                    │  ┌────────────────────┐  │
                    │  │  Risk Calculator   │  │
                    │  └────────────────────┘  │
                    │  ┌────────────────────┐  │
                    │  │ Compliance Mapper  │  │
                    │  └────────────────────┘  │
                    └──────────┬──────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│  AI ENGINE LAYER  │ │  DATA LAYER      │ │  INTEGRATION     │
│                   │ │                  │ │  LAYER           │
│  - Prompt Scanner │ │  - PostgreSQL    │ │                   │
│  - Injection Det. │ │  - Redis Cache   │ │  - Ollama API    │
│  - PII Detector   │ │  - Vector DB     │ │  - OpenAI API    │
│  - Hallucination  │ │  - Object Store  │ │  - HuggingFace   │
│  - Agent Monitor  │ │  - Audit Logs    │ │  - Vector DBs    │
│  - SBOM Analyzer  │ │                  │ │  - Slack/Email   │
└──────────────────┘ └──────────────────┘ └──────────────────┘
```

## 1.2 Architecture Comparison: ASM → AI Shield

| Area | Original ASM | GenAI Security Platform |
|------|--------------------------|---------------------------|
| **Focus** | Attack Surface Management | GenAI Security |
| **Scan Targets** | IPs, Domains, Subdomains, Ports | LLMs, Prompts, Models, Agents |
| **Modules** | 10+ Attack Surface modules | 10 OWASP LLM Top 10 modules |
| **Assets** | Hosts, Services, Certificates | Models, Prompts, Agents, RAG systems |
| **Risk** | CVSS-based scoring | OWASP GenAI Risk Scoring |
| **Compliance** | PCI-DSS, HIPAA, SOC2 | OWASP GenAI, NIST AI RMF, ISO 42001 |
| **Reports** | Security Assessment Reports | AI Security Assessment Reports |

---

# 2. FOLDER STRUCTURE

## 2.1 Backend (Django REST) — Folder Structure

```
genai-security-platform-backend/
│
├── manage.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
│
├── config/                          # Django project config
│   ├── __init__.py
│   ├── settings/
│   │   ├── __init__.py
│   │   ├── base.py                  # Base settings (reused from ASM)
│   │   ├── development.py
│   │   ├── production.py
│   │   └── test.py
│   ├── urls.py                      # Root URL config
│   ├── wsgi.py
│   └── asgi.py
│
├── apps/                            # All Django apps
│   │
│   ├── core/                        # Core/Shared (REUSED FROM ASM)
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── organization.py      # REUSED - Org model
│   │   │   ├── project.py           # REUSED - Project model
│   │   │   ├── user.py              # REUSED - Custom User model
│   │   │   └── audit_log.py         # REUSED - Audit trail
│   │   ├── api/
│   │   │   ├── serializers/
│   │   │   ├── views/
│   │   │   └── urls.py
│   │   ├── permissions.py           # REUSED - RBAC
│   │   ├── authentication.py        # REUSED - JWT Auth
│   │   └── admin.py
│   │
│   ├── organizations/               # REUSED FROM ASM (with additions)
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── organization.py      # REUSED
│   │   │   └── membership.py        # REUSED
│   │   ├── api/
│   │   └── ...
│   │
│   ├── projects/                    # REUSED FROM ASM (with additions)
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── project.py           # REUSED - Updated for AI context
│   │   │   └── project_member.py    # REUSED
│   │   ├── api/
│   │   └── ...
│   │
│   ├── ai_assets/                   # NEW - AI Asset Inventory
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── ai_model.py          # LLM Models (Ollama, OpenAI, etc.)
│   │   │   ├── ai_agent.py          # AI Agents
│   │   │   ├── rag_system.py        # RAG Systems
│   │   │   └── vector_database.py   # Vector DBs
│   │   ├── api/
│   │   │   ├── serializers/
│   │   │   ├── views/
│   │   │   └── urls.py
│   │   ├── services/
│   │   │   ├── model_discovery.py
│   │   │   └── asset_tracker.py
│   │   └── admin.py
│   │
│   ├── prompt_injection/            # NEW - LLM01 Module
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── prompt_scan.py
│   │   │   ├── prompt_risk.py
│   │   │   └── injection_finding.py
│   │   ├── api/
│   │   │   ├── serializers/
│   │   │   ├── views/
│   │   │   └── urls.py
│   │   ├── services/
│   │   │   ├── prompt_scanner.py
│   │   │   ├── injection_detector.py
│   │   │   ├── jailbreak_detector.py
│   │   │   └── sanitizer.py
│   │   └── tests/
│   │
│   ├── sensitive_info/              # NEW - LLM02 Module
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── secret_scan.py
│   │   │   ├── pii_finding.py
│   │   │   └── credential_exposure.py
│   │   ├── api/
│   │   ├── services/
│   │   │   ├── api_key_detector.py
│   │   │   ├── pii_detector.py
│   │   │   └── data_leakage_analyzer.py
│   │   └── tests/
│   │
│   ├── supply_chain/                # NEW - LLM03 Module
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── ai_sbom.py
│   │   │   ├── dependency.py
│   │   │   ├── plugin.py
│   │   │   └── sdk_risk.py
│   │   ├── api/
│   │   ├── services/
│   │   │   ├── sbom_generator.py
│   │   │   ├── dependency_scanner.py
│   │   │   └── sdk_assessor.py
│   │   └── tests/
│   │
│   ├── data_poisoning/              # NEW - LLM04 Module
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── training_data_check.py
│   │   │   ├── rag_validation.py
│   │   │   ├── dataset_integrity.py
│   │   │   └── trust_score.py
│   │   ├── api/
│   │   ├── services/
│   │   │   ├── data_validator.py
│   │   │   ├── poisoning_detector.py
│   │   │   └── trust_scorer.py
│   │   └── tests/
│   │
│   ├── output_handling/             # NEW - LLM05 Module
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── output_sanitization.py
│   │   │   ├── xss_finding.py
│   │   │   └── unsafe_code_finding.py
│   │   ├── api/
│   │   ├── services/
│   │   │   ├── sanitizer.py
│   │   │   ├── xss_detector.py
│   │   │   └── code_gen_validator.py
│   │   └── tests/
│   │
│   ├── excessive_agency/            # NEW - LLM06 Module
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── agent_permission.py
│   │   │   ├── action_approval.py
│   │   │   ├── human_loop_control.py
│   │   │   └── tool_access_log.py
│   │   ├── api/
│   │   ├── services/
│   │   │   ├── permission_manager.py
│   │   │   ├── approval_workflow.py
│   │   │   └── tool_monitor.py
│   │   └── tests/
│   │
│   ├── prompt_leakage/              # NEW - LLM07 Module
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── leakage_scan.py
│   │   │   ├── exposure_test.py
│   │   │   └── prompt_hardening.py
│   │   ├── api/
│   │   ├── services/
│   │   │   ├── leakage_detector.py
│   │   │   ├── exposure_tester.py
│   │   │   └── hardening_scorer.py
│   │   └── tests/
│   │
│   ├── vector_security/             # NEW - LLM08 Module
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── vector_db_security.py
│   │   │   ├── tenant_isolation.py
│   │   │   ├── embedding_exposure.py
│   │   │   └── rag_security.py
│   │   ├── api/
│   │   ├── services/
│   │   │   ├── vector_db_auditor.py
│   │   │   ├── isolation_validator.py
│   │   │   └── retrieval_auditor.py
│   │   └── tests/
│   │
│   ├── hallucination/               # NEW - LLM09 Module
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── hallucination_finding.py
│   │   │   ├── citation_check.py
│   │   │   ├── confidence_score.py
│   │   │   └── response_validation.py
│   │   ├── api/
│   │   ├── services/
│   │   │   ├── hallucination_detector.py
│   │   │   ├── citation_validator.py
│   │   │   └── response_validator.py
│   │   └── tests/
│   │
│   ├── unbounded_consumption/       # NEW - LLM10 Module
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── token_usage.py
│   │   │   ├── cost_monitor.py
│   │   │   ├── dos_detection.py
│   │   │   └── rate_limit_assessment.py
│   │   ├── api/
│   │   ├── services/
│   │   │   ├── token_monitor.py
│   │   │   ├── cost_analyzer.py
│   │   │   ├── dos_detector.py
│   │   │   └── resource_abuse_detector.py
│   │   └── tests/
│   │
│   ├── compliance/                  # NEW (ENHANCED FROM ASM)
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── compliance_framework.py
│   │   │   ├── compliance_mapping.py
│   │   │   ├── compliance_check.py
│   │   │   └── compliance_report.py
│   │   ├── api/
│   │   ├── services/
│   │   │   ├── framework_mapper.py
│   │   │   ├── compliance_calculator.py
│   │   │   └── report_generator.py
│   │   └── tests/
│   │
│   ├── findings/                    # NEW (ENHANCED FROM ASM)
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── finding.py          # Base finding model
│   │   │   ├── risk_score.py
│   │   │   └── trend.py
│   │   ├── api/
│   │   ├── services/
│   │   │   ├── finding_manager.py
│   │   │   ├── risk_calculator.py
│   │   │   └── trend_analyzer.py
│   │   └── tests/
│   │
│   ├── reports/                     # ENHANCED FROM ASM
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── report.py
│   │   │   ├── report_template.py
│   │   │   └── scheduled_report.py
│   │   ├── api/
│   │   ├── services/
│   │   │   ├── report_generator.py
│   │   │   ├── pdf_generator.py
│   │   │   └── export_service.py
│   │   └── tests/
│   │
│   ├── ai_risk_dashboard/           # NEW - Risk Dashboard
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── risk_widget.py
│   │   │   └── risk_trend.py
│   │   ├── api/
│   │   ├── services/
│   │   │   ├── risk_aggregator.py
│   │   │   └── dashboard_service.py
│   │   └── tests/
│   │
│   ├── notifications/               # REUSED FROM ASM (enhanced)
│   │   ├── models/
│   │   ├── services/
│   │   │   ├── email_notifier.py
│   │   │   ├── slack_notifier.py
│   │   │   └── webhook_notifier.py
│   │   └── ...
│   │
│   └── settings/                    # ENHANCED FROM ASM
│       └── ...
│
├── shared/                          # Shared utilities
│   ├── enums.py                     # All enums (reused & new)
│   ├── constants.py
│   ├── exceptions.py
│   ├── mixins.py
│   └── utils/
│       ├── validators.py
│       ├── encryptors.py
│       └── paginators.py
│
└── scripts/
    ├── seed_demo_data.py
    ├── migrate_asm_to_ai_shield.py
    └── scan_runner.py
```

## 2.2 Frontend (React/Angular — REUSE ASM UI) — Folder Structure

```
genai-security-platform-frontend/
│
├── public/
│   └── index.html
│
├── src/
│   ├── index.tsx / main.ts
│   ├── App.tsx
│   ├── router.tsx                    # REUSED from ASM (updated routes)
│   │
│   ├── layouts/                      # REUSED from ASM
│   │   ├── MainLayout.tsx            # Sidebar + Header + Content
│   │   ├── AuthLayout.tsx
│   │   └── components/
│   │       ├── Sidebar.tsx           # REUSED (menu items changed)
│   │       ├── Header.tsx            # REUSED
│   │       ├── Breadcrumb.tsx        # REUSED
│   │       └── NotificationBell.tsx  # REUSED
│   │
│   ├── components/                   # REUSED shared components
│   │   ├── ui/                       # REUSED (buttons, cards, tables, etc.)
│   │   │   ├── Button.tsx
│   │   │   ├── Card.tsx
│   │   │   ├── DataTable.tsx
│   │   │   ├── Badge.tsx
│   │   │   ├── Modal.tsx
│   │   │   ├── Tabs.tsx
│   │   │   ├── StatusIndicator.tsx
│   │   │   ├── RiskScoreBadge.tsx
│   │   │   ├── SearchInput.tsx
│   │   │   ├── FilterPanel.tsx
│   │   │   ├── Pagination.tsx
│   │   │   ├── DateRangePicker.tsx
│   │   │   ├── LoadingSpinner.tsx
│   │   │   └── EmptyState.tsx
│   │   ├── charts/                   # REUSED + NEW
│   │   │   ├── RiskChart.tsx
│   │   │   ├── TrendChart.tsx
│   │   │   ├── PieChart.tsx
│   │   │   ├── ComplianceGauge.tsx
│   │   │   └── HeatMap.tsx
│   │   └── forms/                    # REUSED
│   │       ├── FormField.tsx
│   │       ├── Select.tsx
│   │       ├── MultiSelect.tsx
│   │       └── CodeEditor.tsx        # NEW - For prompt editing
│   │
│   ├── pages/                        # MODIFIED: ASM → AI Shield pages
│   │   ├── auth/                     # REUSED from ASM
│   │   │   ├── LoginPage.tsx
│   │   │   ├── LogoutPage.tsx
│   │   │   ├── ForgotPasswordPage.tsx
│   │   │   └── ResetPasswordPage.tsx
│   │   │
│   │   ├── dashboard/               # NEW - AI Shield Dashboard
│   │   │   ├── DashboardPage.tsx
│   │   │   ├── widgets/
│   │   │   │   ├── RiskSummaryWidget.tsx
│   │   │   │   ├── OWASPCoverageWidget.tsx
│   │   │   │   ├── RecentScansWidget.tsx
│   │   │   │   ├── AssetOverviewWidget.tsx
│   │   │   │   ├── TrendChartWidget.tsx
│   │   │   │   └── ComplianceStatusWidget.tsx
│   │   │   └── hooks/
│   │   │       └── useDashboardData.ts
│   │   │
│   │   ├── organizations/           # REUSED from ASM
│   │   │   ├── OrganizationListPage.tsx
│   │   │   ├── OrganizationDetailPage.tsx
│   │   │   └── OrganizationFormPage.tsx
│   │   │
│   │   ├── projects/                # ENHANCED from ASM
│   │   │   ├── ProjectListPage.tsx
│   │   │   ├── ProjectDetailPage.tsx
│   │   │   └── ProjectFormPage.tsx
│   │   │
│   │   ├── ai-assets/              # NEW - AI Asset Inventory
│   │   │   ├── AssetListPage.tsx
│   │   │   ├── AssetDetailPage.tsx
│   │   │   ├── ModelDiscoveryPage.tsx
│   │   │   └── AssetRegistrationForm.tsx
│   │   │
│   │   ├── scans/                   # MODIFIED: ASM Scans → AI Scans
│   │   │   ├── ScanListPage.tsx
│   │   │   ├── ScanDetailPage.tsx
│   │   │   ├── ScanInitiatePage.tsx
│   │   │   ├── ScanResultPage.tsx
│   │   │   └── components/
│   │   │       ├── ScanStatusBadge.tsx
│   │   │       ├── ScanProgressBar.tsx
│   │   │       └── ScanConfigForm.tsx
│   │   │
│   │   ├── modules/                 # NEW - 10 OWASP Modules
│   │   │   ├── prompt-injection/    # LLM01
│   │   │   │   ├── PromptInjectionPage.tsx
│   │   │   │   ├── PromptScannerPage.tsx
│   │   │   │   ├── InjectionResultsPage.tsx
│   │   │   │   └── components/
│   │   │   │       ├── PromptInput.tsx
│   │   │   │       ├── RiskScoreCard.tsx
│   │   │   │       └── InjectionList.tsx
│   │   │   │
│   │   │   ├── sensitive-info/      # LLM02
│   │   │   │   ├── SensitiveInfoPage.tsx
│   │   │   │   ├── SecretDetectionPage.tsx
│   │   │   │   ├── PIIDetectionPage.tsx
│   │   │   │   └── components/
│   │   │   │       ├── SecretList.tsx
│   │   │   │       └── DataLeakageReport.tsx
│   │   │   │
│   │   │   ├── supply-chain/        # LLM03
│   │   │   │   ├── SupplyChainPage.tsx
│   │   │   │   ├── AISBOMPage.tsx
│   │   │   │   ├── DependencyListPage.tsx
│   │   │   │   └── components/
│   │   │   │       ├── SBOMPreview.tsx
│   │   │   │       └── DependencyTree.tsx
│   │   │   │
│   │   │   ├── data-poisoning/      # LLM04
│   │   │   │   ├── DataPoisoningPage.tsx
│   │   │   │   ├── TrainingDataValidationPage.tsx
│   │   │   │   ├── RAGValidationPage.tsx
│   │   │   │   └── components/
│   │   │   │       ├── DatasetIntegrityCard.tsx
│   │   │   │       └── TrustScoreIndicator.tsx
│   │   │   │
│   │   │   ├── output-handling/     # LLM05
│   │   │   │   ├── OutputHandlingPage.tsx
│   │   │   │   ├── OutputSanitizationPage.tsx
│   │   │   │   ├── XSSDetectionPage.tsx
│   │   │   │   └── components/
│   │   │   │       ├── OutputPreview.tsx
│   │   │   │       └── UnsafeCodeAlert.tsx
│   │   │   │
│   │   │   ├── excessive-agency/    # LLM06
│   │   │   │   ├── ExcessiveAgencyPage.tsx
│   │   │   │   ├── PermissionManagerPage.tsx
│   │   │   │   ├── ApprovalWorkflowPage.tsx
│   │   │   │   └── components/
│   │   │   │       ├── AgentPermissionTable.tsx
│   │   │   │       ├── ActionApprovalCard.tsx
│   │   │   │       └── ToolAccessMonitor.tsx
│   │   │   │
│   │   │   ├── prompt-leakage/      # LLM07
│   │   │   │   ├── PromptLeakagePage.tsx
│   │   │   │   ├── LeakageDetectionPage.tsx
│   │   │   │   ├── ExposureTestingPage.tsx
│   │   │   │   └── components/
│   │   │   │       ├── LeakageResultCard.tsx
│   │   │   │       └── HardeningScoreCard.tsx
│   │   │   │
│   │   │   ├── vector-security/     # LLM08
│   │   │   │   ├── VectorSecurityPage.tsx
│   │   │   │   ├── VectorDBSecurityPage.tsx
│   │   │   │   ├── TenantIsolationPage.tsx
│   │   │   │   └── components/
│   │   │   │       ├── VectorDBConfigCard.tsx
│   │   │   │       └── IsolationStatusTable.tsx
│   │   │   │
│   │   │   ├── hallucination/       # LLM09
│   │   │   │   ├── HallucinationPage.tsx
│   │   │   │   ├── CitationValidationPage.tsx
│   │   │   │   ├── ResponseValidationPage.tsx
│   │   │   │   └── components/
│   │   │   │       ├── HallucinationScoreCard.tsx
│   │   │   │       └── CitationCheckTable.tsx
│   │   │   │
│   │   │   └── unbounded-consumption/ # LLM10
│   │   │       ├── UnboundedConsumptionPage.tsx
│   │   │       ├── TokenUsageMonitorPage.tsx
│   │   │       ├── CostAnalysisPage.tsx
│   │   │       ├── DoSDetectionPage.tsx
│   │   │       └── components/
│   │   │           ├── UsageChart.tsx
│   │   │           ├── CostBreakdown.tsx
│   │   │           └── AnomalyAlert.tsx
│   │   │
│   │   ├── findings/                # ENHANCED from ASM
│   │   │   ├── FindingListPage.tsx
│   │   │   ├── FindingDetailPage.tsx
│   │   │   └── components/
│   │   │       ├── FindingCard.tsx
│   │   │       ├── RiskMatrix.tsx
│   │   │       └── RemediationGuide.tsx
│   │   │
│   │   ├── compliance/              # NEW - Compliance Module
│   │   │   ├── ComplianceDashboardPage.tsx
│   │   │   ├── FrameworkDetailPage.tsx
│   │   │   ├── ComplianceReportPage.tsx
│   │   │   ├── ControlMappingPage.tsx
│   │   │   └── components/
│   │   │       ├── FrameworkCard.tsx
│   │   │       ├── ComplianceGauge.tsx
│   │   │       └── ControlChecklist.tsx
│   │   │
│   │   ├── reports/                 # ENHANCED from ASM
│   │   │   ├── ReportListPage.tsx
│   │   │   ├── ReportBuilderPage.tsx
│   │   │   ├── ReportViewerPage.tsx
│   │   │   └── components/
│   │   │       ├── ReportTemplateSelector.tsx
│   │   │       ├── ExecutiveSummary.tsx
│   │   │       └── ExportOptions.tsx
│   │   │
│   │   ├── ai-agent-center/         # NEW - AI Agent Security Center
│   │   │   ├── AgentCenterPage.tsx
│   │   │   ├── AgentDetailPage.tsx
│   │   │   ├── AgentMonitorPage.tsx
│   │   │   └── components/
│   │   │       ├── AgentCard.tsx
│   │   │       ├── PermissionMatrix.tsx
│   │   │       ├── ToolUsageTimeline.tsx
│   │   │       └── CommandLog.tsx
│   │   │
│   │   └── settings/                # ENHANCED from ASM
│   │       ├── SettingsPage.tsx
│   │       ├── SecuritySettingsPage.tsx
│   │       ├── IntegrationSettingsPage.tsx
│   │       ├── NotificationSettingsPage.tsx
│   │       ├── APISettingsPage.tsx
│   │       └── UserManagementPage.tsx
│   │
│   ├── services/                    # API services
│   │   ├── apiClient.ts             # REUSED from ASM
│   │   ├── authService.ts           # REUSED from ASM
│   │   ├── dashboardService.ts      # NEW
│   │   ├── assetService.ts          # NEW
│   │   ├── scanService.ts           # MODIFIED
│   │   ├── moduleServices/          # NEW - One per module
│   │   │   ├── promptInjectionService.ts
│   │   │   ├── sensitiveInfoService.ts
│   │   │   ├── supplyChainService.ts
│   │   │   ├── dataPoisoningService.ts
│   │   │   ├── outputHandlingService.ts
│   │   │   ├── excessiveAgencyService.ts
│   │   │   ├── promptLeakageService.ts
│   │   │   ├── vectorSecurityService.ts
│   │   │   ├── hallucinationService.ts
│   │   │   └── unboundedConsumptionService.ts
│   │   ├── complianceService.ts     # NEW
│   │   ├── reportService.ts         # ENHANCED
│   │   ├── agentService.ts          # NEW
│   │   └── notificationService.ts   # REUSED
│   │
│   ├── hooks/                       # Custom hooks
│   │   ├── useAuth.ts               # REUSED
│   │   ├── useOrganizations.ts      # REUSED
│   │   ├── useProjects.ts           # REUSED
│   │   ├── useScans.ts              # MODIFIED
│   │   ├── useAiAssets.ts           # NEW
│   │   ├── useFindings.ts           # ENHANCED
│   │   ├── useCompliance.ts         # NEW
│   │   ├── useReports.ts            # ENHANCED
│   │   ├── useWebSocket.ts          # REUSED
│   │   └── usePermissions.ts        # REUSED
│   │
│   ├── store/                       # State management (REUSED pattern)
│   │   ├── index.ts
│   │   ├── authSlice.ts             # REUSED
│   │   ├── organizationSlice.ts     # REUSED
│   │   ├── projectSlice.ts          # REUSED
│   │   ├── scanSlice.ts             # MODIFIED
│   │   ├── findingSlice.ts          # ENHANCED
│   │   ├── assetSlice.ts            # NEW
│   │   ├── complianceSlice.ts       # NEW
│   │   └── notificationSlice.ts     # REUSED
│   │
│   ├── utils/
│   │   ├── formatters.ts            # REUSED + NEW
│   │   ├── validators.ts            # REUSED
│   │   ├── permissions.ts           # REUSED
│   │   ├── constants.ts             # MODIFIED
│   │   └── helpers.ts               # REUSED
│   │
│   └── styles/                      # REUSED from ASM + NEW
│       ├── globals.css
│       ├── variables.css
│       ├── components/
│       │   ├── buttons.css
│       │   ├── cards.css
│       │   ├── tables.css
│       │   ├── forms.css
│       │   └── modals.css
│       └── pages/
│           ├── dashboard.css
│           ├── scans.css
│           └── modules.css          # NEW
│
├── package.json
├── tsconfig.json
├── vite.config.ts / webpack.config.js
└── .env.example
```

---

# 3. DATABASE SCHEMA

## 3.1 Core Models (REUSED from ASM — Minimal Changes)

```sql
-- =====================================================
-- REUSED FROM ASM (with minor modifications)
-- =====================================================

-- Organizations (REUSED)
CREATE TABLE organizations_organization (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    logo_url VARCHAR(500),
    industry VARCHAR(100),
    website VARCHAR(500),
    is_active BOOLEAN DEFAULT TRUE,
    subscription_tier VARCHAR(50) DEFAULT 'free',   -- NEW: added 'ai_shield_tiers'
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Users (REUSED)
CREATE TABLE core_user (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(254) UNIQUE NOT NULL,
    username VARCHAR(150) UNIQUE NOT NULL,
    password_hash VARCHAR(128) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    avatar_url VARCHAR(500),
    is_active BOOLEAN DEFAULT TRUE,
    is_superuser BOOLEAN DEFAULT FALSE,
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Organization Memberships (REUSED)
CREATE TABLE organizations_membership (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations_organization(id) ON DELETE CASCADE,
    user_id UUID REFERENCES core_user(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL DEFAULT 'member',  -- 'admin', 'member', 'viewer', 'auditor'
    is_default BOOLEAN DEFAULT FALSE,
    joined_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(organization_id, user_id)
);

-- Projects (REUSED - added ai_context fields)
CREATE TABLE projects_project (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations_organization(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    project_type VARCHAR(50) DEFAULT 'ai_security',  -- MODIFIED: from 'asm' to 'ai_security'
    status VARCHAR(50) DEFAULT 'active',
    ai_context JSONB DEFAULT '{}',                     -- NEW: AI-specific context
    metadata JSONB DEFAULT '{}',                       -- REUSED
    created_by_id UUID REFERENCES core_user(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Audit Log (REUSED)
CREATE TABLE core_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations_organization(id) ON DELETE CASCADE,
    user_id UUID REFERENCES core_user(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id UUID,
    details JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

## 3.2 AI Asset Models (NEW)

```sql
-- =====================================================
-- NEW: AI ASSET INVENTORY
-- =====================================================

-- AI Models (LLMs)
CREATE TABLE ai_assets_ai_model (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations_organization(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects_project(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    model_type VARCHAR(50) NOT NULL,  -- 'ollama', 'openai', 'gemini', 'claude', 'huggingface', 'custom'
    model_family VARCHAR(100),         -- 'gpt-4', 'claude-3', 'llama-3', 'gemini-1.5'
    version VARCHAR(100),
    endpoint_url VARCHAR(500),
    api_key_ref VARCHAR(255),          -- Reference to encrypted key
    context_window INTEGER,            -- Max context window size
    capabilities JSONB DEFAULT '{}',   -- ['chat', 'completion', 'embedding', 'vision']
    risk_score DECIMAL(5,2) DEFAULT 0,
    discovery_method VARCHAR(50),      -- 'manual', 'auto_discovered', 'api_scan'
    metadata JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE,
    last_scanned_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- AI Agents
CREATE TABLE ai_assets_ai_agent (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations_organization(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects_project(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    agent_type VARCHAR(100),           -- 'autonomous', 'assistant', 'workflow', 'custom'
    model_id UUID REFERENCES ai_assets_ai_model(id) ON DELETE SET NULL,
    description TEXT,
    permissions JSONB DEFAULT '{}',    -- What agent can access/do
    tools JSONB DEFAULT '[]',          -- Available tools
    allowed_actions JSONB DEFAULT '[]',
    disallowed_actions JSONB DEFAULT '[]',
    human_approval_required BOOLEAN DEFAULT FALSE,
    risk_level VARCHAR(50) DEFAULT 'medium',
    status VARCHAR(50) DEFAULT 'active',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- RAG Systems
CREATE TABLE ai_assets_rag_system (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations_organization(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects_project(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    vector_db_id UUID,                 -- FK to vector_database
    embedding_model_id UUID REFERENCES ai_assets_ai_model(id) ON DELETE SET NULL,
    chunking_strategy VARCHAR(100),
    chunk_size INTEGER,
    chunk_overlap INTEGER,
    retrieval_config JSONB DEFAULT '{}',
    security_config JSONB DEFAULT '{}', -- Isolation, access controls
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Vector Databases
CREATE TABLE ai_assets_vector_database (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations_organization(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    db_type VARCHAR(50) NOT NULL,      -- 'pinecone', 'weaviate', 'qdrant', 'chroma', 'pgvector'
    endpoint_url VARCHAR(500),
    tenant_id VARCHAR(255),            -- Multi-tenant isolation ID
    dimension INTEGER,                 -- Vector dimension
    indexing_method VARCHAR(100),
    security_config JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

## 3.3 Scan & Findings Models (NEW — Based on OWASP Modules)

```sql
-- =====================================================
-- NEW: AI SECURITY SCANS (Generic Scan Framework)
-- =====================================================

-- AI Scans (Replaces ASM Scans)
CREATE TABLE scans_ai_scan (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations_organization(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects_project(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    scan_type VARCHAR(100) NOT NULL,   -- 'prompt_injection', 'sensitive_info', 'supply_chain',
                                       -- 'data_poisoning', 'output_handling', 'excessive_agency',
                                       -- 'prompt_leakage', 'vector_security', 'hallucination',
                                       -- 'unbounded_consumption', 'full_assessment'
    status VARCHAR(50) DEFAULT 'pending', -- 'pending', 'running', 'completed', 'failed', 'cancelled'
    target_type VARCHAR(50),           -- 'model', 'prompt', 'agent', 'rag', 'vector_db', 'dataset'
    target_id UUID,                    -- Polymorphic target
    config JSONB DEFAULT '{}',         -- Scan configuration
    progress DECIMAL(5,2) DEFAULT 0,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_message TEXT,
    created_by_id UUID REFERENCES core_user(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Base Findings (Polymorphic via JSONB)
CREATE TABLE findings_finding (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations_organization(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects_project(id) ON DELETE SET NULL,
    scan_id UUID REFERENCES scans_ai_scan(id) ON DELETE SET NULL,
    module_type VARCHAR(50) NOT NULL,   -- 'llm01', 'llm02', ... 'llm10'
    finding_type VARCHAR(100) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,      -- 'critical', 'high', 'medium', 'low', 'info'
    cvss_score DECIMAL(3,1),
    owasp_category VARCHAR(100),
    status VARCHAR(50) DEFAULT 'open',  -- 'open', 'in_progress', 'resolved', 'false_positive'
    evidence JSONB DEFAULT '{}',        -- Module-specific evidence
    remediation TEXT,
    references JSONB DEFAULT '[]',
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    resolved_by_id UUID REFERENCES core_user(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- LLM01: Prompt Injection
-- =====================================================
CREATE TABLE prompt_injection_prompt_scan (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans_ai_scan(id) ON DELETE CASCADE,
    prompt_text TEXT NOT NULL,
    is_malicious BOOLEAN DEFAULT FALSE,
    risk_score DECIMAL(5,2) DEFAULT 0,
    injection_type VARCHAR(100),        -- 'direct', 'indirect', 'jailbreak', 'role_play', 'context_leak'
    techniques_detected JSONB DEFAULT '[]',
    sanitized_prompt TEXT,
    detection_details JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- LLM02: Sensitive Information Disclosure
-- =====================================================
CREATE TABLE sensitive_info_secret_scan (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans_ai_scan(id) ON DELETE CASCADE,
    content_type VARCHAR(100),           -- 'api_key', 'password', 'token', 'pii', 'credential'
    detected_value_hash VARCHAR(255),
    secret_type VARCHAR(100),
    source VARCHAR(255),                 -- 'prompt', 'training_data', 'model_output', 'config'
    risk_level VARCHAR(20),
    context_snippet TEXT,
    is_validated BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- LLM03: Supply Chain Security
-- =====================================================
CREATE TABLE supply_chain_ai_sbom (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations_organization(id) ON DELETE CASCADE,
    model_id UUID REFERENCES ai_assets_ai_model(id) ON DELETE CASCADE,
    sbom_version VARCHAR(50),
    format VARCHAR(50) DEFAULT 'cyclonedx',
    components JSONB DEFAULT '[]',       -- List of dependencies
    vulnerabilities JSONB DEFAULT '[]',
    risk_score DECIMAL(5,2) DEFAULT 0,
    generated_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- LLM04: Data and Model Poisoning
-- =====================================================
CREATE TABLE data_poisoning_validation (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans_ai_scan(id) ON DELETE CASCADE,
    data_source VARCHAR(255),            -- 'training', 'rag_document', 'fine_tuning'
    data_fingerprint VARCHAR(255),
    integrity_score DECIMAL(5,2),
    anomalies_detected JSONB DEFAULT '[]',
    tampering_indicators JSONB DEFAULT '[]',
    trust_score DECIMAL(5,2),
    validation_status VARCHAR(50),
    details JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- LLM05: Improper Output Handling
-- =====================================================
CREATE TABLE output_handling_finding (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans_ai_scan(id) ON DELETE CASCADE,
    output_type VARCHAR(100),            -- 'html', 'code', 'markdown', 'text'
    is_sanitized BOOLEAN,
    vulnerability_type VARCHAR(100),     -- 'xss', 'unsafe_html', 'code_injection', 'prompt_injection'
    payload_preview TEXT,
    risk_level VARCHAR(20),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- LLM06: Excessive Agency
-- =====================================================
CREATE TABLE excessive_agency_agent_permission (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES ai_assets_ai_agent(id) ON DELETE CASCADE,
    permission_name VARCHAR(255),
    resource_type VARCHAR(100),
    action VARCHAR(100),                 -- 'read', 'write', 'execute', 'admin'
    is_granted BOOLEAN DEFAULT FALSE,
    justification TEXT,
    risk_score DECIMAL(5,2),
    requires_human_approval BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE excessive_agency_action_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES ai_assets_ai_agent(id) ON DELETE CASCADE,
    action VARCHAR(255),
    parameters JSONB DEFAULT '{}',
    status VARCHAR(50),                  -- 'pending', 'approved', 'rejected', 'executed', 'blocked'
    risk_assessment JSONB DEFAULT '{}',
    approved_by_id UUID REFERENCES core_user(id) ON DELETE SET NULL,
    executed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- LLM07: System Prompt Leakage
-- =====================================================
CREATE TABLE prompt_leakage_scan (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans_ai_scan(id) ON DELETE CASCADE,
    system_prompt_hash VARCHAR(255),
    leakage_found BOOLEAN DEFAULT FALSE,
    leaked_content TEXT,
    exposure_type VARCHAR(100),          -- 'extraction', 'inference', 'error_message'
    prompt_hardening_score DECIMAL(5,2),
    recommendations JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- LLM08: Vector and Embedding Security
-- =====================================================
CREATE TABLE vector_security_assessment (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vector_db_id UUID REFERENCES ai_assets_vector_database(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans_ai_scan(id) ON DELETE CASCADE,
    tenant_isolation_valid BOOLEAN,
    embedding_exposure_found BOOLEAN,
    rag_security_score DECIMAL(5,2),
    retrieval_security_score DECIMAL(5,2),
    findings JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- LLM09: Misinformation and Hallucination
-- =====================================================
CREATE TABLE hallucination_finding (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans_ai_scan(id) ON DELETE CASCADE,
    input_text TEXT,
    output_text TEXT,
    hallucination_score DECIMAL(5,2),
    hallucination_type VARCHAR(100),     -- 'factual_error', 'unsupported_claim', 'contradiction', 'made_up'
    confidence_score DECIMAL(5,2),
    citations_valid BOOLEAN,
    trusted_sources JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- LLM10: Unbounded Consumption
-- =====================================================
CREATE TABLE unbounded_consumption_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations_organization(id) ON DELETE CASCADE,
    model_id UUID REFERENCES ai_assets_ai_model(id) ON DELETE SET NULL,
    agent_id UUID REFERENCES ai_assets_ai_agent(id) ON DELETE SET NULL,
    tokens_used INTEGER DEFAULT 0,
    cost DECIMAL(12,6) DEFAULT 0,
    requests_count INTEGER DEFAULT 0,
    avg_response_time_ms DECIMAL(10,2),
    peak_usage JSONB DEFAULT '{}',
    anomalies JSONB DEFAULT '[]',
    recorded_at TIMESTAMPTZ DEFAULT NOW()
);
```

## 3.4 Compliance Models (NEW)

```sql
-- =====================================================
-- NEW: COMPLIANCE MODULE
-- =====================================================

-- Compliance Frameworks
CREATE TABLE compliance_framework (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    short_name VARCHAR(50) NOT NULL,     -- 'owasp_genai', 'nist_ai_rmf', 'iso_42001', 'iso_27001', 'mitre_atlas'
    version VARCHAR(50),
    description TEXT,
    icon_url VARCHAR(500),
    total_controls INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Compliance Controls
CREATE TABLE compliance_control (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_id UUID REFERENCES compliance_framework(id) ON DELETE CASCADE,
    control_id VARCHAR(100) NOT NULL,     -- e.g., 'OWASP-GENAI-LLM01-01'
    title VARCHAR(500) NOT NULL,
    description TEXT,
    category VARCHAR(255),
    risk_category VARCHAR(100),           -- Maps to OWASP LLM categories
    implementation_guidance TEXT,
    verification_method VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(framework_id, control_id)
);

-- Compliance Mapping (Findings → Controls)
CREATE TABLE compliance_mapping (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations_organization(id) ON DELETE CASCADE,
    finding_id UUID REFERENCES findings_finding(id) ON DELETE CASCADE,
    control_id UUID REFERENCES compliance_control(id) ON DELETE CASCADE,
    framework_id UUID REFERENCES compliance_framework(id) ON DELETE CASCADE,
    mapping_type VARCHAR(50) DEFAULT 'automated',
    confidence_score DECIMAL(5,2),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(finding_id, control_id)
);

-- Compliance Check Results
CREATE TABLE compliance_check_result (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations_organization(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects_project(id) ON DELETE SET NULL,
    framework_id UUID REFERENCES compliance_framework(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans_ai_scan(id) ON DELETE SET NULL,
    control_id UUID REFERENCES compliance_control(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL,         -- 'compliant', 'non_compliant', 'not_applicable', 'not_tested'
    evidence JSONB DEFAULT '{}',
    notes TEXT,
    checked_at TIMESTAMPTZ DEFAULT NOW()
);

-- Compliance Reports
CREATE TABLE compliance_report (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations_organization(id) ON DELETE CASCADE,
    framework_id UUID REFERENCES compliance_framework(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    report_type VARCHAR(50),             -- 'full', 'summary', 'gap_analysis'
    overall_score DECIMAL(5,2),
    control_summary JSONB DEFAULT '{}',
    findings_summary JSONB DEFAULT '{}',
    generated_at TIMESTAMPTZ DEFAULT NOW(),
    created_by_id UUID REFERENCES core_user(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

## 3.5 Reports Models (ENHANCED from ASM)

```sql
-- Reports (ENHANCED from ASM)
CREATE TABLE reports_report (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations_organization(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects_project(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    report_type VARCHAR(50) NOT NULL,    -- 'executive', 'technical', 'owasp_compliance', 'risk_assessment'
    format VARCHAR(50) DEFAULT 'pdf',    -- 'pdf', 'docx', 'html', 'csv', 'json'
    config JSONB DEFAULT '{}',           -- Report generation config
    status VARCHAR(50) DEFAULT 'draft',
    file_url VARCHAR(500),
    generated_at TIMESTAMPTZ,
    created_by_id UUID REFERENCES core_user(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

## 3.6 Entity-Relationship Diagram (Text)

```
organizations_organization
    │
    ├── projects_project
    │       │
    │       ├── ai_assets_ai_model
    │       ├── ai_assets_ai_agent (→ model)
    │       ├── ai_assets_rag_system (→ vector_db, embedding_model)
    │       ├── ai_assets_vector_database
    │       ├── scans_ai_scan
    │       │       ├── prompt_injection_prompt_scan
    │       │       ├── sensitive_info_secret_scan
    │       │       ├── data_poisoning_validation
    │       │       ├── output_handling_finding
    │       │       ├── prompt_leakage_scan
    │       │       ├── vector_security_assessment
    │       │       ├── hallucination_finding
    │       │       └── findings_finding
    │       │
    │       ├── findings_finding
    │       │       └── compliance_mapping → compliance_control
    │       │
    │       ├── compliance_check_result
    │       ├── compliance_report
    │       └── reports_report
    │
    ├── supply_chain_ai_sbom (→ model)
    ├── unbounded_consumption_usage (→ model, agent)
    ├── excessive_agency_agent_permission (→ agent)
    ├── excessive_agency_action_log (→ agent)
    ├── compliance_framework
    │       └── compliance_control
    │               └── compliance_mapping
    │
    └── core_audit_log
```

---

# 4. API DESIGN

## 4.1 API Versioning & Base URL

```
Base URL: /api/v1/
Authentication: JWT Bearer Token (REUSED from ASM)
Content-Type: application/json
```

## 4.2 Complete API Endpoints

### Core APIs (REUSED from ASM)

```
AUTH
  POST   /auth/login/
  POST   /auth/logout/
  POST   /auth/refresh/
  POST   /auth/forgot-password/
  POST   /auth/reset-password/
  GET    /auth/me/
  PUT    /auth/me/
  GET    /auth/permissions/

ORGANIZATIONS (REUSED)
  GET    /organizations/
  POST   /organizations/
  GET    /organizations/{id}/
  PUT    /organizations/{id}/
  DELETE /organizations/{id}/
  GET    /organizations/{id}/members/
  POST   /organizations/{id}/members/
  DELETE /organizations/{id}/members/{member_id}/
  PATCH  /organizations/{id}/members/{member_id}/role/

PROJECTS (ENHANCED)
  GET    /projects/
  POST   /projects/
  GET    /projects/{id}/
  PUT    /projects/{id}/
  DELETE /projects/{id}/
  GET    /projects/{id}/scans/
  GET    /projects/{id}/findings/
  GET    /projects/{id}/assets/
  GET    /projects/{id}/compliance/
  GET    /projects/{id}/dashboard/
```

### AI Asset APIs (NEW)

```
AI MODELS
  GET    /ai-assets/models/
  POST   /ai-assets/models/
  GET    /ai-assets/models/{id}/
  PUT    /ai-assets/models/{id}/
  DELETE /ai-assets/models/{id}/
  POST   /ai-assets/models/{id}/scan/
  GET    /ai-assets/models/{id}/scans/
  POST   /ai-assets/models/discover/         # Auto-discover models
  GET    /ai-assets/models/{id}/sbom/

AI AGENTS
  GET    /ai-assets/agents/
  POST   /ai-assets/agents/
  GET    /ai-assets/agents/{id}/
  PUT    /ai-assets/agents/{id}/
  DELETE /ai-assets/agents/{id}/
  GET    /ai-assets/agents/{id}/permissions/
  PUT    /ai-assets/agents/{id}/permissions/
  GET    /ai-assets/agents/{id}/activity/
  POST   /ai-assets/agents/{id}/scan/

RAG SYSTEMS
  GET    /ai-assets/rag-systems/
  POST   /ai-assets/rag-systems/
  GET    /ai-assets/rag-systems/{id}/
  PUT    /ai-assets/rag-systems/{id}/
  DELETE /ai-assets/rag-systems/{id}/
  POST   /ai-assets/rag-systems/{id}/scan/

VECTOR DATABASES
  GET    /ai-assets/vector-dbs/
  POST   /ai-assets/vector-dbs/
  GET    /ai-assets/vector-dbs/{id}/
  PUT    /ai-assets/vector-dbs/{id}/
  DELETE /ai-assets/vector-dbs/{id}/
  POST   /ai-assets/vector-dbs/{id}/scan/
  GET    /ai-assets/vector-dbs/{id}/isolation-check/
```

### Security Scan APIs (NEW — Replaces ASM Scans)

```
SCANS
  GET    /scans/
  POST   /scans/
  GET    /scans/{id}/
  PUT    /scans/{id}/
  DELETE /scans/{id}/
  POST   /scans/{id}/start/
  POST   /scans/{id}/cancel/
  GET    /scans/{id}/results/
  GET    /scans/{id}/progress/             # WebSocket for real-time
  GET    /scans/{id}/findings/
  GET    /scans/templates/                 # Scan templates
  POST   /scans/quick-scan/                # Quick scan on target
```

### OWASP Module APIs (NEW)

```
LLM01 — PROMPT INJECTION
  POST   /modules/llm01/scan-prompt/
  POST   /modules/llm01/scan-batch/
  POST   /modules/llm01/sanitize/
  GET    /modules/llm01/results/
  GET    /modules/llm01/results/{id}/
  POST   /modules/llm01/detect-indirect/
  POST   /modules/llm01/detect-jailbreak/
  GET    /modules/llm01/statistics/

LLM02 — SENSITIVE INFORMATION DISCLOSURE
  POST   /modules/llm02/scan-secrets/
  POST   /modules/llm02/scan-pii/
  POST   /modules/llm02/analyze-leakage/
  GET    /modules/llm02/results/
  GET    /modules/llm02/results/{id}/
  POST   /modules/llm02/validate-secret/
  GET    /modules/llm02/statistics/

LLM03 — SUPPLY CHAIN SECURITY
  POST   /modules/llm03/generate-sbom/
  POST   /modules/llm03/scan-dependencies/
  POST   /modules/llm03/assess-sdk/
  GET    /modules/llm03/sboms/
  GET    /modules/llm03/sboms/{id}/
  GET    /modules/llm03/dependencies/
  GET    /modules/llm03/statistics/

LLM04 — DATA AND MODEL POISONING
  POST   /modules/llm04/validate-training-data/
  POST   /modules/llm04/validate-rag-documents/
  POST   /modules/llm04/check-integrity/
  GET    /modules/llm04/validations/
  GET    /modules/llm04/validations/{id}/
  GET    /modules/llm04/trust-scores/
  GET    /modules/llm04/statistics/

LLM05 — IMPROPER OUTPUT HANDLING
  POST   /modules/llm05/sanitize-output/
  POST   /modules/llm05/detect-xss/
  POST   /modules/llm05/detect-unsafe-code/
  GET    /modules/llm05/results/
  GET    /modules/llm05/results/{id}/
  GET    /modules/llm05/statistics/

LLM06 — EXCESSIVE AGENCY
  GET    /modules/llm06/permissions/
  POST   /modules/llm06/permissions/review/
  PUT    /modules/llm06/permissions/{id}/
  GET    /modules/llm06/approvals/
  POST   /modules/llm06/approvals/
  PUT    /modules/llm06/approvals/{id}/respond/
  GET    /modules/llm06/activity-log/
  GET    /modules/llm06/statistics/

LLM07 — SYSTEM PROMPT LEAKAGE
  POST   /modules/llm07/scan-leakage/
  POST   /modules/llm07/exposure-test/
  POST   /modules/llm07/calculate-hardening/
  GET    /modules/llm07/results/
  GET    /modules/llm07/results/{id}/
  GET    /modules/llm07/statistics/

LLM08 — VECTOR AND EMBEDDING SECURITY
  POST   /modules/llm08/assess-vector-db/
  POST   /modules/llm08/validate-isolation/
  POST   /modules/llm08/detect-exposure/
  POST   /modules/llm08/assess-rag/
  GET    /modules/llm08/assessments/
  GET    /modules/llm08/assessments/{id}/
  GET    /modules/llm08/statistics/

LLM09 — MISINFORMATION & HALLUCINATION
  POST   /modules/llm09/detect-hallucination/
  POST   /modules/llm09/validate-citations/
  POST   /modules/llm09/validate-response/
  GET    /modules/llm09/results/
  GET    /modules/llm09/results/{id}/
  GET    /modules/llm09/statistics/

LLM10 — UNBOUNDED CONSUMPTION
  GET    /modules/llm10/usage/
  GET    /modules/llm10/costs/
  POST   /modules/llm10/detect-dos/
  GET    /modules/llm10/anomalies/
  GET    /modules/llm10/rate-limits/
  GET    /modules/llm10/statistics/
```

### Findings & Risk APIs (ENHANCED from ASM)

```
FINDINGS
  GET    /findings/
  GET    /findings/{id}/
  PATCH  /findings/{id}/status/
  PATCH  /findings/{id}/assign/
  POST   /findings/{id}/notes/
  GET    /findings/{id}/history/
  GET    /findings/summary/
  GET    /findings/trends/
  GET    /findings/export/?format=csv|pdf|json

RISK DASHBOARD
  GET    /risk-dashboard/overview/
  GET    /risk-dashboard/trends/
  GET    /risk-dashboard/owasp-coverage/
  GET    /risk-dashboard/by-module/
  GET    /risk-dashboard/by-severity/
```

### Compliance APIs (NEW)

```
COMPLIANCE
  GET    /compliance/frameworks/
  GET    /compliance/frameworks/{id}/
  GET    /compliance/frameworks/{id}/controls/
  GET    /compliance/frameworks/{id}/controls/{control_id}/
  GET    /compliance/projects/{project_id}/status/
  POST   /compliance/projects/{project_id}/run-check/
  GET    /compliance/reports/
  POST   /compliance/reports/
  GET    /compliance/reports/{id}/
  GET    /compliance/mappings/
  POST   /compliance/mappings/  # Map finding to control
  GET    /compliance/statistics/
```

### Reports APIs (ENHANCED from ASM)

```
REPORTS
  GET    /reports/
  POST   /reports/
  GET    /reports/{id}/
  PUT    /reports/{id}/
  DELETE /reports/{id}/
  POST   /reports/{id}/generate/
  GET    /reports/{id}/download/?format=pdf|docx|html
  GET    /reports/templates/
  POST   /reports/scheduled/
  GET    /reports/scheduled/
  DELETE /reports/scheduled/{id}/
```

### AI Agent Security Center APIs (NEW)

```
AI AGENT SECURITY CENTER
  GET    /agent-center/overview/
  GET    /agent-center/agents/
  GET    /agent-center/agents/{id}/
  GET    /agent-center/permissions/
  PUT    /agent-center/permissions/{id}/
  GET    /agent-center/activity/
  GET    /agent-center/alerts/
  POST   /agent-center/alerts/{id}/acknowledge/
  GET    /agent-center/statistics/
```

### Settings APIs (ENHANCED from ASM)

```
SETTINGS
  GET    /settings/general/
  PUT    /settings/general/
  GET    /settings/integrations/
  POST   /settings/integrations/
  DELETE /settings/integrations/{id}/
  GET    /settings/notifications/
  PUT    /settings/notifications/
  GET    /settings/api-keys/
  POST   /settings/api-keys/
  DELETE /settings/api-keys/{id}/
  GET    /settings/ai-engines/           # Configure AI detection engines
  PUT    /settings/ai-engines/{engine}/
  GET    /settings/scan-defaults/
  PUT    /settings/scan-defaults/
```

---

# 5. DASHBOARD DESIGN

## 5.1 Main Dashboard Layout

```
┌─────────────────────────────────────────────────────────────────────────┐
│ [SIDEBAR] │                        HEADER                              │
│           │  [Org Selector] [Search] [Notifications 🔔] [User 👤]      │
├───────────┤─────────────────────────────────────────────────────────────┤
│           │                                                             │
│  [Logo]   │  ┌─────────────────────────────────────────────────────────┐│
│           │  │  AI RISK OVERVIEW                          [Time Range] ││
│  Dashboard │  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌────────────┐  ││
│  ▶┐       │  │  │Total │ │Crit. │ │High  │ │OWASP │ │Compliance  │  ││
│    AI      │  │  │Risks  │ │Risks │ │Risks │ │Cover.│ │Score       │  ││
│    Assets  │  │  │ 1,234 │ │  89  │ │ 345  │ │  72% │ │   68%      │  ││
│  ▶┐       │  │  └──────┘ └──────┘ └──────┘ └──────┘ └────────────┘  ││
│    Scans   │  └─────────────────────────────────────────────────────────┘│
│  ▶┐       │                                                             │
│    OWASP   │  ┌──────────────────────────┐ ┌──────────────────────────┐  │
│    Modules │  │  RISK BY MODULE          │ │  OWASP COVERAGE          │  │
│  ▶┐       │  │                          │ │  ┌──────────────────┐    │  │
│    Find.   │  │  LLM01 ████████████ 89%  │ │  │     GAUGE       │    │  │
│    Compl.  │  │  LLM02 ████████     65%  │ │  │   72% Covered   │    │  │
│    Reports │  │  LLM03 ███████████  78%  │ │  │   ████████████   │    │  │
│    Agent   │  │  LLM04 ██████       55%  │ │  └──────────────────┘    │  │
│    Center  │  │  LLM05 █████████    72%  │ └──────────────────────────┘  │
│           │  │  ...                      │                             │
│  Settings  │  └──────────────────────────┘                             │
│           │                                                           │
│  [Help]   │  ┌──────────────────────────┐ ┌──────────────────────────┐  │
│  [Logout] │  │  TREND ANALYSIS          │ │  RECENT SCANS            │  │
│           │  │                          │ │  ┌────────────────────┐  │  │
│           │  │  ┌───┐ ┌───┐ ┌───┐      │ │  │ Scan #1    ✓ Done │  │  │
│           │  │  │▁▂▃▅│ │▂▃▁▄│ │▃▅▇▆│   │ │  │ Scan #2    ▶ Run │  │  │
│           │  │  └───┘ └───┘ └───┘      │ │  │ Scan #3    ❌ Fail│  │  │
│           │  │  [Week][Month][Quarter]  │ │  │ ...                │  │  │
│           │  └──────────────────────────┘ │  └────────────────────┘  │  │
│           │                               └──────────────────────────┘  │
│           │                                                             │
│           │  ┌─────────────────────────────────────────────────────────┐│
│           │  │  RECENT FINDINGS                                       ││
│           │  │  ┌────┬────────────────────────┬────────┬───────────┐  ││
│           │  │  │ #  │ Finding                │ Module │ Severity  │  ││
│           │  │  ├────┼────────────────────────┼────────┼───────────┤  ││
│           │  │  │ 1  │ Prompt Injection       │ LLM01  │ 🔴 CRIT   │  ││
│           │  │  │ 2  │ API Key Exposed        │ LLM02  │ 🟠 HIGH   │  ││
│           │  │  │ 3  │ Unsafe Code Gen.       │ LLM05  │ 🟡 MED    │  ││
│           │  │  └────┴────────────────────────┴────────┴───────────┘  ││
│           │  └─────────────────────────────────────────────────────────┘│
│           │                                                             │
└───────────┴─────────────────────────────────────────────────────────────┘
```

## 5.2 Dashboard Widget Components

| Widget | Type | Data Source |
|--------|------|-------------|
| Total Risks | Stat Card | findings_finding (aggregated) |
| Critical Risks | Stat Card | findings_finding (severity=critical) |
| High Risks | Stat Card | findings_finding (severity=high) |
| OWASP Coverage | Gauge | compliance_mapping / frameworks |
| Compliance Score | Gauge | compliance_check_result |
| Risk by Module | Bar Chart | findings_finding (grouped by module) |
| OWASP Coverage by Module | Progress Bars | compliance_mapping |
| Trend Analysis | Line Chart | findings_finding (by week/month) |
| Recent Scans | List | scans_ai_scan (latest 5) |
| Recent Findings | Table | findings_finding (latest 10) |
| Asset Overview | Stat Card | ai_assets_* (counts) |
| Active Agents | Stat Card | ai_assets_ai_agent (active) |

---

# 6. SIDEBAR MENU STRUCTURE

## 6.1 Compare: ASM Menu → AI Shield Menu

```
┌──────────────────────┐  ┌──────────────────────────────────┐
│  QUANTUMSEC ASM      │  │  QUANTUMSEC AI SHIELD            │
│  (Original)          │  │  (Converted)                      │
├──────────────────────┤  ├──────────────────────────────────┤
│                      │  │                                   │
│  🔲 Dashboard        │  │  🔲 Dashboard                     │
│                      │  │                                   │
│  🏢 Organizations    │  │  🏢 Organizations  [REUSED]       │
│  📁 Projects         │  │  📁 Projects       [ENHANCED]    │
│                      │  │                                   │
│  🌐 Attack Surface   │  │  🤖 AI Assets      [NEW]         │
│    ├ Subdomains      │  │    ├ LLM Models                  │
│    ├ IPs             │  │    ├ AI Agents                   │
│    ├ Ports           │  │    ├ RAG Systems                 │
│    ├ Technologies    │  │    └ Vector Databases             │
│    └ Certificates    │  │                                   │
│                      │  │  🔬 AI Security Scans [NEW]      │
│  📡 Scans            │  │    ├ All Scans                   │
│  📊 Findings         │  │    ├ Scan Templates              │
│  📈 Reports          │  │    └ Quick Scan                  │
│                      │  │                                   │
│  ✅ Compliance       │  │  🛡️ OWASP Modules    [NEW]       │
│  ⚙️ Settings         │  │    ├ LLM01 Prompt Injection      │
│                      │  │    ├ LLM02 Sensitive Info        │
│                      │  │    ├ LLM03 Supply Chain          │
│                      │  │    ├ LLM04 Data Poisoning        │
│                      │  │    ├ LLM05 Output Handling       │
│                      │  │    ├ LLM06 Excessive Agency      │
│                      │  │    ├ LLM07 Prompt Leakage        │
│                      │  │    ├ LLM08 Vector Security       │
│                      │  │    ├ LLM09 Hallucination         │
│                      │  │    └ LLM10 Unbounded Consumption │
│                      │  │                                   │
│                      │  │  🔍 AI Findings     [NEW]        │
│                      │  │  📋 Compliance      [ENHANCED]   │
│                      │  │    ├ OWASP GenAI                 │
│                      │  │    ├ NIST AI RMF                 │
│                      │  │    ├ ISO 42001                   │
│                      │  │    ├ ISO 27001                   │
│                      │  │    └ MITRE ATLAS                 │
│                      │  │                                   │
│                      │  │  📊 Reports          [ENHANCED]  │
│                      │  │    ├ Executive Report            │
│                      │  │    ├ Technical Report            │
│                      │  │    ├ OWASP Compliance            │
│                      │  │    └ AI Risk Assessment          │
│                      │  │                                   │
│                      │  │  🎯 AI Agent Center  [NEW]       │
│                      │  │    ├ Agents Overview             │
│                      │  │    ├ Permissions                 │
│                      │  │    └ Activity Log                │
│                      │  │                                   │
│                      │  │  ⚙️ Settings         [ENHANCED]  │
│                      │  │    ├ General                     │
│                      │  │    ├ AI Engines                  │
│                      │  │    ├ Integrations                │
│                      │  │    ├ Notifications               │
│                      │  │    └ API Keys                    │
│                      │  │                                   │
└──────────────────────┘  └──────────────────────────────────┘
```

## 6.2 Sidebar Menu JSON Structure (for Frontend Config)

```json
{
  "menuItems": [
    {
      "id": "dashboard",
      "label": "Dashboard",
      "icon": "LayoutDashboard",
      "path": "/dashboard",
      "permission": "view_dashboard",
      "badge": null
    },
    {
      "id": "organizations",
      "label": "Organizations",
      "icon": "Building2",
      "path": "/organizations",
      "permission": "view_organizations",
      "badge": null
    },
    {
      "id": "projects",
      "label": "Projects",
      "icon": "FolderKanban",
      "path": "/projects",
      "permission": "view_projects",
      "badge": null
    },
    {
      "id": "ai-assets",
      "label": "AI Assets",
      "icon": "Brain",
      "path": "/ai-assets",
      "permission": "view_ai_assets",
      "badge": null,
      "children": [
        { "id": "ai-models", "label": "LLM Models", "path": "/ai-assets/models" },
        { "id": "ai-agents", "label": "AI Agents", "path": "/ai-assets/agents" },
        { "id": "rag-systems", "label": "RAG Systems", "path": "/ai-assets/rag-systems" },
        { "id": "vector-dbs", "label": "Vector Databases", "path": "/ai-assets/vector-dbs" }
      ]
    },
    {
      "id": "scans",
      "label": "AI Security Scans",
      "icon": "Shield",
      "path": "/scans",
      "permission": "view_scans",
      "badge": "count_running_scans",
      "children": [
        { "id": "all-scans", "label": "All Scans", "path": "/scans" },
        { "id": "scan-templates", "label": "Scan Templates", "path": "/scans/templates" },
        { "id": "quick-scan", "label": "Quick Scan", "path": "/scans/quick" }
      ]
    },
    {
      "id": "modules",
      "label": "OWASP Modules",
      "icon": "ShieldCheck",
      "path": "/modules",
      "permission": "view_modules",
      "badge": "critical_findings_count",
      "children": [
        { "id": "llm01", "label": "LLM01 Prompt Injection", "path": "/modules/prompt-injection" },
        { "id": "llm02", "label": "LLM02 Sensitive Info", "path": "/modules/sensitive-info" },
        { "id": "llm03", "label": "LLM03 Supply Chain", "path": "/modules/supply-chain" },
        { "id": "llm04", "label": "LLM04 Data Poisoning", "path": "/modules/data-poisoning" },
        { "id": "llm05", "label": "LLM05 Output Handling", "path": "/modules/output-handling" },
        { "id": "llm06", "label": "LLM06 Excessive Agency", "path": "/modules/excessive-agency" },
        { "id": "llm07", "label": "LLM07 Prompt Leakage", "path": "/modules/prompt-leakage" },
        { "id": "llm08", "label": "LLM08 Vector Security", "path": "/modules/vector-security" },
        { "id": "llm09", "label": "LLM09 Hallucination", "path": "/modules/hallucination" },
        { "id": "llm10", "label": "LLM10 Unbounded Consumption", "path": "/modules/unbounded-consumption" }
      ]
    },
    {
      "id": "findings",
      "label": "AI Findings",
      "icon": "AlertTriangle",
      "path": "/findings",
      "permission": "view_findings",
      "badge": "open_findings_count"
    },
    {
      "id": "compliance",
      "label": "Compliance",
      "icon": "ClipboardCheck",
      "path": "/compliance",
      "permission": "view_compliance",
      "badge": null,
      "children": [
        { "id": "dashboard-c", "label": "Compliance Dashboard", "path": "/compliance" },
        { "id": "owasp-genai", "label": "OWASP GenAI", "path": "/compliance/owasp-genai" },
        { "id": "nist-ai-rmf", "label": "NIST AI RMF", "path": "/compliance/nist-ai-rmf" },
        { "id": "iso-42001", "label": "ISO 42001", "path": "/compliance/iso-42001" },
        { "id": "iso-27001", "label": "ISO 27001", "path": "/compliance/iso-27001" },
        { "id": "mitre-atlas", "label": "MITRE ATLAS", "path": "/compliance/mitre-atlas" }
      ]
    },
    {
      "id": "reports",
      "label": "Reports",
      "icon": "FileText",
      "path": "/reports",
      "permission": "view_reports",
      "badge": null,
      "children": [
        { "id": "all-reports", "label": "All Reports", "path": "/reports" },
        { "id": "executive-report", "label": "Executive Report", "path": "/reports/executive" },
        { "id": "technical-report", "label": "Technical Report", "path": "/reports/technical" },
        { "id": "owasp-compliance-report", "label": "OWASP Compliance", "path": "/reports/owasp-compliance" },
        { "id": "risk-assessment-report", "label": "Risk Assessment", "path": "/reports/risk-assessment" }
      ]
    },
    {
      "id": "agent-center",
      "label": "AI Agent Center",
      "icon": "Bot",
      "path": "/agent-center",
      "permission": "view_agent_center",
      "badge": null,
      "children": [
        { "id": "agents-overview", "label": "Agents Overview", "path": "/agent-center" },
        { "id": "permissions", "label": "Permissions", "path": "/agent-center/permissions" },
        { "id": "activity-log", "label": "Activity Log", "path": "/agent-center/activity" }
      ]
    },
    {
      "id": "settings",
      "label": "Settings",
      "icon": "Settings",
      "path": "/settings",
      "permission": "view_settings",
      "children": [
        { "id": "general", "label": "General", "path": "/settings" },
        { "id": "ai-engines", "label": "AI Engines", "path": "/settings/ai-engines" },
        { "id": "integrations", "label": "Integrations", "path": "/settings/integrations" },
        { "id": "notifications", "label": "Notifications", "path": "/settings/notifications" },
        { "id": "api-keys", "label": "API Keys", "path": "/settings/api-keys" }
      ]
    }
  ]
}
```

---

# 7. BACKEND MODELS DETAIL

## 7.1 Django Model Classes (Key App Implementations)

### App: `ai_assets`

```python
# models/ai_model.py
class AIModel(models.Model):
    MODEL_TYPES = [
        ('ollama', 'Ollama'),
        ('openai', 'OpenAI'),
        ('gemini', 'Gemini'),
        ('claude', 'Claude'),
        ('huggingface', 'HuggingFace'),
        ('custom', 'Custom'),
    ]

    organization = models.ForeignKey('organizations.Organization', on_delete=models.CASCADE)
    project = models.ForeignKey('projects.Project', on_delete=models.SET_NULL, null=True, blank=True)
    name = models.CharField(max_length=255)
    model_type = models.CharField(max_length=50, choices=MODEL_TYPES)
    model_family = models.CharField(max_length=100, blank=True)
    version = models.CharField(max_length=100, blank=True)
    endpoint_url = models.URLField(max_length=500, blank=True)
    api_key_ref = models.CharField(max_length=255, blank=True)  # Encrypted reference
    context_window = models.IntegerField(default=4096)
    capabilities = models.JSONField(default=dict)  # ['chat', 'completion', 'embedding', 'vision']
    risk_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    discovery_method = models.CharField(max_length=50, default='manual')
    metadata = models.JSONField(default=dict)
    is_active = models.BooleanField(default=True)
    last_scanned_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "AI Model"
        verbose_name_plural = "AI Models"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['organization', 'model_type']),
            models.Index(fields=['organization', 'is_active']),
        ]
```

### App: `findings`

```python
# models/finding.py
class Finding(models.Model):
    MODULE_TYPES = [
        ('llm01', 'LLM01 - Prompt Injection'),
        ('llm02', 'LLM02 - Sensitive Information Disclosure'),
        ('llm03', 'LLM03 - Supply Chain Security'),
        ('llm04', 'LLM04 - Data and Model Poisoning'),
        ('llm05', 'LLM05 - Improper Output Handling'),
        ('llm06', 'LLM06 - Excessive Agency'),
        ('llm07', 'LLM07 - System Prompt Leakage'),
        ('llm08', 'LLM08 - Vector and Embedding Security'),
        ('llm09', 'LLM09 - Misinformation and Hallucination'),
        ('llm10', 'LLM10 - Unbounded Consumption'),
    ]

    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]

    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    ]

    organization = models.ForeignKey('organizations.Organization', on_delete=models.CASCADE)
    project = models.ForeignKey('projects.Project', on_delete=models.SET_NULL, null=True, blank=True)
    scan = models.ForeignKey('scans.AIScan', on_delete=models.SET_NULL, null=True, blank=True)
    module_type = models.CharField(max_length=50, choices=MODULE_TYPES)
    finding_type = models.CharField(max_length=100)
    title = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    cvss_score = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)
    owasp_category = models.CharField(max_length=100, blank=True)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='open')
    evidence = models.JSONField(default=dict)
    remediation = models.TextField(blank=True)
    references = models.JSONField(default=list)
    discovered_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey('core.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='resolved_findings')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Finding"
        verbose_name_plural = "Findings"
        ordering = ['-discovered_at']
        indexes = [
            models.Index(fields=['organization', 'module_type', 'severity']),
            models.Index(fields=['organization', 'status']),
            models.Index(fields=['scan']),
        ]
```

### App: `scans`

```python
# models/scan.py
class AIScan(models.Model):
    SCAN_TYPES = [
        ('prompt_injection', 'Prompt Injection Scan'),
        ('sensitive_info', 'Sensitive Info Scan'),
        ('supply_chain', 'Supply Chain Scan'),
        ('data_poisoning', 'Data Poisoning Scan'),
        ('output_handling', 'Output Handling Scan'),
        ('excessive_agency', 'Excessive Agency Scan'),
        ('prompt_leakage', 'Prompt Leakage Scan'),
        ('vector_security', 'Vector Security Scan'),
        ('hallucination', 'Hallucination Scan'),
        ('unbounded_consumption', 'Unbounded Consumption Scan'),
        ('full_assessment', 'Full Security Assessment'),
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]

    organization = models.ForeignKey('organizations.Organization', on_delete=models.CASCADE)
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    scan_type = models.CharField(max_length=50, choices=SCAN_TYPES)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='pending')
    target_type = models.CharField(max_length=50, blank=True)
    target_id = models.UUIDField(null=True, blank=True)
    config = models.JSONField(default=dict)
    progress = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    created_by = models.ForeignKey('core.User', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "AI Scan"
        verbose_name_plural = "AI Scans"
        ordering = ['-created_at']
```

### App: `compliance`

```python
# models/framework.py
class ComplianceFramework(models.Model):
    name = models.CharField(max_length=255)
    short_name = models.CharField(max_length=50, unique=True)
    version = models.CharField(max_length=50, blank=True)
    description = models.TextField(blank=True)
    icon_url = models.URLField(max_length=500, blank=True)
    total_controls = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.short_name})"

    class Meta:
        verbose_name = "Compliance Framework"
        verbose_name_plural = "Compliance Frameworks"


class ComplianceControl(models.Model):
    framework = models.ForeignKey(ComplianceFramework, on_delete=models.CASCADE, related_name='controls')
    control_id = models.CharField(max_length=100)
    title = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    category = models.CharField(max_length=255, blank=True)
    risk_category = models.CharField(max_length=100, blank=True)
    implementation_guidance = models.TextField(blank=True)
    verification_method = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['framework', 'control_id']
        ordering = ['framework', 'control_id']
```

---

# 8. SECURITY SCAN WORKFLOW

## 8.1 End-to-End Scan Flow

```
USER ACTION                    BACKEND                           AI ENGINE
    │                              │                                 │
    │  1. Configure Scan           │                                 │
    │  ───────────────────────────►│                                 │
    │                              │  2. Create AIScan record        │
    │                              │     (status: pending)           │
    │                              │                                 │
    │  3. Start Scan               │                                 │
    │  ───────────────────────────►│                                 │
    │                              │  4. Update status → 'running'   │
    │                              │  5. Dispatch to Celery Task     │
    │                              │  ──────────────────────────────►│
    │                              │                                 │
    │                              │                                 │  6. Initialize Engine
    │                              │                                 │  7. Load scan config
    │                              │                                 │  8. Connect to target
    │                              │                                 │
    │  ◄─── 9. WebSocket: Progress ─── (periodically) ──────────────│
    │                              │                                 │
    │                              │                                 │  10. Run detection
    │                              │                                 │  11. Score findings
    │                              │                                 │  12. Generate evidence
    │                              │                                 │
    │                              │  13. Store findings             │
    │                              │  ◄──────────────────────────────│
    │                              │                                 │
    │                              │  14. Map findings to OWASP     │
    │                              │  15. Calculate risk score      │
    │                              │  16. Update compliance         │
    │                              │  17. Update status → 'completed'│
    │                              │                                 │
    │  ◄─── 18. Results ready ─────│                                 │
    │                              │                                 │
    │  19. View results            │                                 │
    │  ───────────────────────────►│                                 │
    │                              │  20. Return findings + score    │
    │  ◄───────────────────────────│                                 │
    │                              │                                 │
```

## 8.2 Scan Orchestration Sequence

```
┌──────────┐    ┌────────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────────┐
│  User    │    │   API      │    │ ScanOrchestr.│    │ AIEngine     │    │  Database  │
│  (FE)    │    │  View      │    │   (Celery)   │    │  (Service)   │    │            │
└────┬─────┘    └─────┬──────┘    └──────┬───────┘    └──────┬───────┘    └──────┬─────┘
     │                │                  │                   │                   │
     │ POST /scans/   │                  │                   │                   │
     │────────────────►                  │                   │                   │
     │                │                  │                   │                   │
     │                │ Save Scan        │                   │                   │
     │                │─────────────────────────────────────────────────────────►│
     │                │                  │                   │                   │
     │ 201 Created    │                  │                   │                   │
     │◄───────────────│                  │                   │                   │
     │                │                  │                   │                   │
     │ POST /scans/   │                  │                   │                   │
     │ {id}/start/    │                  │                   │                   │
     │────────────────►                  │                   │                   │
     │                │                  │                   │                   │
     │                │ Update → running │                   │                   │
     │                │─────────────────────────────────────────────────────────►│
     │                │                  │                   │                   │
     │                │ Dispatch Task    │                   │                   │
     │                │─────────────────►│                   │                   │
     │                │                  │                   │                   │
     │                │                  │ Initialize Engine │                   │
     │                │                  │──────────────────►│                   │
     │                │                  │                   │                   │
     │ 202 Accepted   │                  │                   │                   │
     │◄───────────────│                  │                   │                   │
     │                │                  │                   │                   │
     │  WEBSOCKET     │                  │  Progress Updates │                   │
     │◄═══════════════╪══════════════════╪═══════════════════│                   │
     │  {progress: %}  │                  │                   │                   │
     │                │                  │                   │                   │
     │                │                  │                   │ Run Detection     │
     │                │                  │                   ├───────────────────┤
     │                │                  │                   │ Analyze & Score   │
     │                │                  │                   ├───────────────────┤
     │                │                  │                   │ Generate Findings │
     │                │                  │                   │                   │
     │                │                  │  Return Results   │                   │
     │                │                  │◄──────────────────│                   │
     │                │                  │                   │                   │
     │                │                  │ Save Findings     │                   │
     │                │                  │───────────────────────────────────────►│
     │                │                  │                   │                   │
     │                │                  │ Map to Compliance │                   │
     │                │                  │───────────────────────────────────────►│
     │                │                  │                   │                   │
     │                │                  │ Update → completed│                   │
     │                │                  │───────────────────────────────────────►│
     │                │                  │                   │                   │
     │  WEBSOCKET     │                  │                   │                   │
     │◄═══════════════╪══════════════════│                   │                   │
     │  {status: done} │                  │                   │                   │
     │                │                  │                   │                   │
     │ GET /scans/    │                  │                   │                   │
     │ {id}/results/  │                  │                   │                   │
     │────────────────►                  │                   │                   │
     │                │ Fetch Results    │                   │                   │
     │                │◄─────────────────────────────────────────────────────────│
     │                │                  │                   │                   │
     │ 200 OK + Results                  │                   │                   │
     │◄───────────────│                  │                   │                   │
```

## 8.3 Scan Types & Their Workflows

| Scan Type | Target | Detection Method | Scoring |
|-----------|--------|-----------------|---------|
| Prompt Injection | Prompt text | Regex patterns + ML classifier | Risk score 0-100 |
| Sensitive Info | Prompt/Output/Config | Regex patterns + entropy check | Severity: Critical-High |
| Supply Chain | Model dependencies | SBOM generator + CVE DB | CVSS-based |
| Data Poisoning | Training data, RAG docs | Statistical anomaly + integrity hash | Trust score |
| Output Handling | Model output | XSS scanner + code analyzer | Severity: Critical-Info |
| Excessive Agency | Agent config | Permission audit + risk matrix | Risk level |
| Prompt Leakage | System prompts | Extraction testing + inference check | Hardening score |
| Vector Security | Vector DB config | Configuration audit + isolation test | Security score |
| Hallucination | Model responses | Cross-reference + fact-check | Confidence score |
| Unbounded Consumption | Usage logs | Anomaly detection + threshold analysis | Risk score |

---

# 9. AI SECURITY ENGINE DESIGN

## 9.1 Engine Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       AI SECURITY ENGINE                                 │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                      ENGINE MANAGER                                  │ │
│  │  - Scan Lifecycle Management                                        │ │
│  │  - Plugin Registry                                                   │ │
│  │  - Result Aggregator                                                 │ │
│  │  - Error Handler                                                     │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                              │                                            │
│        ┌─────────────────────┼─────────────────────┐                     │
│        ▼                     ▼                     ▼                      │
│  ┌──────────┐        ┌──────────────┐      ┌──────────────┐              │
│  │PROMPT    │        │ DETECTION    │      │ VALIDATION   │              │
│  │SCANNER   │        │ PLUGINS      │      │ PLUGINS      │              │
│  │          │        │              │      │              │              │
│  │- Prompt  │        │- Injection   │      │- SBOM        │              │
│  │  Input   │        │- PII/Screts  │      │  Validator   │              │
│  │- Batch   │        │- XSS         │      │- Citation    │              │
│  │  Scanner │        │- Hallucin.   │      │  Checker     │              │
│  │- Sanitiz.│        │- Anomaly     │      │- Integrity   │              │
│  └──────────┘        └──────────────┘      │  Verifier    │              │
│                                             └──────────────┘              │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                      ANALYSIS PIPELINE                                │ │
│  │                                                                       │ │
│  │  [Raw Input] → [Preprocessor] → [Detector] → [Scorer] → [Output]    │ │
│  │                                       ↓                               │ │
│  │                                [Evidence Store]                       │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                      INTEGRATIONS                                     │ │
│  │                                                                       │ │
│  │  Ollama API  │  OpenAI API  │  HuggingFace  │  Vector DB Clients    │ │
│  │  Slack/Email │  Webhooks    │  SIEM Systems  │  Custom Scripts       │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

## 9.2 Key Engine Components

```python
# services/engine_manager.py
class AISecurityEngine:
    """Central engine for orchestrating all AI security scans."""

    def __init__(self, scan: AIScan):
        self.scan = scan
        self.plugins = self._load_plugins()
        self.detectors = self._load_detectors()

    def run_scan(self) -> Dict[str, Any]:
        """Execute the full scan pipeline."""
        # 1. Prepare target
        target = self._resolve_target()

        # 2. Run detection plugins
        raw_results = []
        for detector in self._get_detectors_for_scan_type():
            result = detector.detect(target)
            raw_results.append(result)

        # 3. Analyze & score
        scored_results = self._score_findings(raw_results)

        # 4. Generate evidence
        evidence = self._generate_evidence(scored_results)

        # 5. Map to OWASP categories
        mapped = self._map_to_owasp(evidence)

        # 6. Calculate risk scores
        risk = self._calculate_risk(mapped)

        # 7. Store findings
        findings = self._save_findings(mapped, risk)

        # 8. Update compliance mappings
        self._update_compliance(findings)

        return {
            'findings': findings,
            'risk_score': risk['overall'],
            'module_scores': risk['module_scores'],
            'owasp_coverage': risk['owasp_coverage'],
            'summary': self._generate_summary(findings)
        }

    def _get_detectors_for_scan_type(self) -> List:
        mapping = {
            'prompt_injection': [
                PromptInjectionDetector,
                JailbreakDetector,
                IndirectInjectionDetector,
            ],
            'sensitive_info': [
                APIKeyDetector,
                PIIDetector,
                CredentialScanner,
                DataLeakageAnalyzer,
            ],
            'supply_chain': [
                DependencyScanner,
                SBOMGenerator,
                SDKAssessor,
            ],
            'data_poisoning': [
                TrainingDataValidator,
                RAGDocumentValidator,
                IntegrityVerifier,
            ],
            'output_handling': [
                XSSDetector,
                UnsafeCodeDetector,
                OutputSanitizer,
            ],
            'excessive_agency': [
                PermissionAuditor,
                ActionRiskAnalyzer,
                ToolUsageMonitor,
            ],
            'prompt_leakage': [
                PromptExtractionTester,
                InferenceDetector,
                HardeningScorer,
            ],
            'vector_security': [
                VectorDBAuditor,
                IsolationValidator,
                EmbeddingExposureDetector,
            ],
            'hallucination': [
                HallucinationDetector,
                CitationValidator,
                ResponseValidator,
            ],
            'unbounded_consumption': [
                TokenUsageAnalyzer,
                CostMonitor,
                DoSDetector,
                AnomalyDetector,
            ],
        }
        return mapping.get(self.scan.scan_type, [])
```

## 9.3 Detection Plugin Interface

```python
# interfaces/detector.py
class BaseDetector(ABC):
    """Abstract base for all AI security detection plugins."""

    @abstractmethod
    def detect(self, target: Any) -> DetectionResult:
        """Run detection against target."""
        pass

    @abstractmethod
    def get_confidence(self) -> float:
        """Return confidence score for this detection."""
        pass

    @abstractmethod
    def get_risk_score(self) -> float:
        """Return calculated risk score (0-100)."""
        pass


@dataclass
class DetectionResult:
    is_vulnerable: bool
    vulnerability_type: str
    severity: str  # critical, high, medium, low, info
    confidence: float
    risk_score: float
    evidence: Dict[str, Any]
    details: Dict[str, Any]
    remediation: str
    references: List[str]
```

## 9.4 Example Detector Implementations

```python
# services/prompt_injection/injection_detector.py
class PromptInjectionDetector(BaseDetector):
    """Detects prompt injection attacks in LLM inputs."""

    def __init__(self):
        self.injection_patterns = self._load_patterns()
        self.classifier = self._load_ml_classifier()

    def detect(self, target: PromptTarget) -> DetectionResult:
        prompt_text = target.prompt_text

        # 1. Pattern matching
        pattern_matches = self._match_patterns(prompt_text)

        # 2. ML-based classification
        ml_score = self.classifier.predict_risk(prompt_text)

        # 3. Combined scoring
        risk_score = self._calculate_combined_score(
            pattern_matches, ml_score
        )

        # 4. Determine severity
        severity = self._severity_from_score(risk_score)

        return DetectionResult(
            is_vulnerable=risk_score > 30,
            vulnerability_type='prompt_injection',
            severity=severity,
            confidence=ml_score,
            risk_score=risk_score,
            evidence={
                'matched_patterns': pattern_matches,
                'ml_classification_score': ml_score,
                'detected_techniques': self._classify_techniques(prompt_text),
            },
            details={
                'prompt_length': len(prompt_text),
                'injection_type': self._determine_injection_type(prompt_text),
            },
            remediation="Apply input sanitization and use a prompt firewall."
        )
```

```python
# services/sensitive_info/pii_detector.py
class PIIDetector(BaseDetector):
    """Detects PII and sensitive information in text."""

    PATTERNS = {
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone': r'\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'credit_card': r'\b(?:\d[ -]*?){13,16}\b',
        'api_key': r'\b(sk-[a-zA-Z0-9]{20,}|pk-[a-zA-Z0-9]{20,}|[A-Za-z0-9]{32,})\b',
    }

    def detect(self, target: TextTarget) -> DetectionResult:
        findings = []
        for pii_type, pattern in self.PATTERNS.items():
            matches = re.findall(pattern, target.text)
            if matches:
                findings.append({
                    'type': pii_type,
                    'count': len(matches),
                    'risk_level': self._get_pii_risk(pii_type),
                })

        return DetectionResult(
            is_vulnerable=len(findings) > 0,
            vulnerability_type='pii_exposure',
            severity=self._max_severity(findings),
            confidence=0.95,
            risk_score=self._calculate_risk(findings),
            evidence={'findings': findings},
            details={'total_exposures': len(findings)},
            remediation="Mask or redact PII before sending to LLMs."
        )
```

---

# 10. FRONTEND COMPONENT ARCHITECTURE

## 10.1 Component Hierarchy (React)

```
<App>
  <AuthProvider>
    <OrganizationProvider>
      <ProjectProvider>
        <Router>
          <Routes>
            {/* AUTH LAYOUT */}
            <Route element={<AuthLayout />}>
              <Route path="/login" element={<LoginPage />} />
              <Route path="/forgot-password" element={<ForgotPasswordPage />} />
              <Route path="/reset-password" element={<ResetPasswordPage />} />
            </Route>

            {/* MAIN LAYOUT (REUSED from ASM) */}
            <Route element={<ProtectedRoute><MainLayout /></ProtectedRoute>}>
              <Route path="/dashboard" element={<DashboardPage />} />

              {/* Organizations (REUSED) */}
              <Route path="/organizations" element={<OrganizationListPage />} />
              <Route path="/organizations/:id" element={<OrganizationDetailPage />} />

              {/* Projects (ENHANCED) */}
              <Route path="/projects" element={<ProjectListPage />} />
              <Route path="/projects/:id" element={<ProjectDetailPage />} />

              {/* AI Assets (NEW) */}
              <Route path="/ai-assets" element={<Navigate to="models" />} />
              <Route path="/ai-assets/models" element={<AssetListPage type="models" />} />
              <Route path="/ai-assets/agents" element={<AssetListPage type="agents" />} />
              <Route path="/ai-assets/rag-systems" element={<AssetListPage type="rag" />} />
              <Route path="/ai-assets/vector-dbs" element={<AssetListPage type="vector-db" />} />

              {/* Scans (MODIFIED) */}
              <Route path="/scans" element={<ScanListPage />} />
              <Route path="/scans/quick" element={<ScanInitiatePage />} />
              <Route path="/scans/:id" element={<ScanDetailPage />} />
              <Route path="/scans/:id/results" element={<ScanResultPage />} />

              {/* OWASP Modules (NEW) */}
              <Route path="/modules/prompt-injection/*" element={<PromptInjectionPage />} />
              <Route path="/modules/sensitive-info/*" element={<SensitiveInfoPage />} />
              <Route path="/modules/supply-chain/*" element={<SupplyChainPage />} />
              <Route path="/modules/data-poisoning/*" element={<DataPoisoningPage />} />
              <Route path="/modules/output-handling/*" element={<OutputHandlingPage />} />
              <Route path="/modules/excessive-agency/*" element={<ExcessiveAgencyPage />} />
              <Route path="/modules/prompt-leakage/*" element={<PromptLeakagePage />} />
              <Route path="/modules/vector-security/*" element={<VectorSecurityPage />} />
              <Route path="/modules/hallucination/*" element={<HallucinationPage />} />
              <Route path="/modules/unbounded-consumption/*" element={<UnboundedConsumptionPage />} />

              {/* Findings (ENHANCED) */}
              <Route path="/findings" element={<FindingListPage />} />
              <Route path="/findings/:id" element={<FindingDetailPage />} />

              {/* Compliance (NEW) */}
              <Route path="/compliance" element={<ComplianceDashboardPage />} />
              <Route path="/compliance/:framework" element={<FrameworkDetailPage />} />

              {/* Reports (ENHANCED) */}
              <Route path="/reports" element={<ReportListPage />} />
              <Route path="/reports/:id" element={<ReportViewerPage />} />

              {/* AI Agent Center (NEW) */}
              <Route path="/agent-center" element={<AgentCenterPage />} />
              <Route path="/agent-center/:id" element={<AgentDetailPage />} />

              {/* Settings (ENHANCED) */}
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="/settings/*" element={<SettingsPage />} />
            </Route>
          </Routes>
        </Router>
      </ProjectProvider>
    </OrganizationProvider>
  </AuthProvider>
</App>
```

## 10.2 Key Reusable Components (from ASM)

| Component | Reuse | Modification |
|-----------|-------|-------------|
| `MainLayout` | ✅ Full reuse | Update menu config |
| `Sidebar` | ✅ Full reuse | Swap menu items |
| `Header` | ✅ Full reuse | Update branding |
| `DataTable` | ✅ Full reuse | Same interface |
| `Card` | ✅ Full reuse | Same interface |
| `Button` | ✅ Full reuse | Same interface |
| `Modal` | ✅ Full reuse | Same interface |
| `Badge` | ✅ Full reuse | Add AI risk colors |
| `StatusIndicator` | ✅ Full reuse | Add scan statuses |
| `SearchInput` | ✅ Full reuse | Same interface |
| `FilterPanel` | ✅ Full reuse | Same interface |
| `Pagination` | ✅ Full reuse | Same interface |
| `DateRangePicker` | ✅ Full reuse | Same interface |

## 10.3 New Module Page Pattern (All 10 OWASP Modules)

Each module page follows this pattern:

```
┌───────────────────────────────────────────────────────────┐
│  OWASP Module Header                                       │
│  [Module Icon] LLM01 - Prompt Injection                    │
│  [Description text] [Risk Score] [Last Scanned]            │
│                                                            │
│  ┌─────────────────────── Action Bar ────────────────────┐ │
│  │ [▶ New Scan] [📋 View All] [📊 Stats] [⚙️ Settings]  │ │
│  └───────────────────────────────────────────────────────┘ │
│                                                            │
│  ┌─────────────────────── Quick Actions ──────────────────┐ │
│  │ ┌─────────────────┐ ┌─────────────────┐               │ │
│  │ │ Scan a Prompt    │ │ Scan in Bulk    │               │ │
│  │ │ [Input Box]     │ │ [Upload File]   │               │ │
│  │ └─────────────────┘ └─────────────────┘               │ │
│  └───────────────────────────────────────────────────────┘ │
│                                                            │
│  ┌─────────────────────── Recent Results ─────────────────┐ │
│  │ ┌────┬───────────────┬──────────┬───────┬───────────┐ │ │
│  │ │ #  │ Target        │ Risk     │ Date  │ Status    │ │ │
│  │ ├────┼───────────────┼──────────┼───────┼───────────┤ │ │
│  │ │ 1  │ prompt_1.txt │ 85 (CRIT)│ 06/15 │ Completed │ │ │
│  │ │ 2  │ input.txt    │ 42 (MED) │ 06/14 │ Completed │ │ │
│  │ └────┴───────────────┴──────────┴───────┴───────────┘ │ │
│  └───────────────────────────────────────────────────────┘ │
│                                                            │
│  ┌─────────────────────── Statistics ─────────────────────┐ │
│  │ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │ │
│  │ │ Total    │ │ Critical  │ │  High    │ │ Avg Risk ↓│ │ │
│  │ │ 147      │ │    12     │ │   34     │ │   52%    │  │ │
│  │ └──────────┘ └──────────┘ └──────────┘ └──────────┘  │ │
│  └───────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────┘
```

---

# 11. STEP-BY-STEP IMPLEMENTATION ROADMAP

## Phase 1: Foundation (Weeks 1-2)

| Step | Task | Details | Effort |
|------|------|---------|--------|
| 1.1 | **Project Setup** | Clone Original ASM, rename to `genai-security-platform`, update branding | 1 day |
| 1.2 | **Core Models Update** | Add AI context fields to Project model, add modular module_type | 1 day |
| 1.3 | **Database Migration** | Run initial schema migrations for new apps | 0.5 day |
| 1.4 | **Sidebar Menu Update** | Replace ASM menu with AI Shield menu in frontend config | 0.5 day |
| 1.5 | **Branding Refresh** | Update logo, app name, colors, favicon to "GenAI Security Platform" | 0.5 day |
| 1.6 | **Auth/Org Reuse** | Verify authentication and organization management work unchanged | 0.5 day |

## Phase 2: Core Infrastructure (Weeks 3-4)

| Step | Task | Details | Effort |
|------|------|---------|--------|
| 2.1 | **AI Assets App** | Create `ai_assets` app with models, APIs, serializers, views | 2 days |
| 2.2 | **Scan Framework** | Create `scans` app with generic scan model, API, Celery task | 2 days |
| 2.3 | **Findings App** | Create `findings` app with polymorphic findings model | 1.5 days |
| 2.4 | **AI Security Engine** | Create engine manager, detector interface, plugin registry | 2 days |
| 2.5 | **WebSocket Integration** | Real-time scan progress via Django Channels | 1 day |
| 2.6 | **Dashboard API** | Aggregation endpoints for dashboard widgets | 1 day |

## Phase 3: OWASP Modules (Weeks 5-8)

| Step | Task | Details | Effort |
|------|------|---------|--------|
| 3.1 | **LLM01 — Prompt Injection** | Scanner, patterns, ML classifier, sanitizer, jailbreak detection | 3 days |
| 3.2 | **LLM02 — Sensitive Info** | API key/PII/secret detectors, regex patterns, entropy check | 2 days |
| 3.3 | **LLM03 — Supply Chain** | SBOM generator, dependency scanner, CVE integration | 2 days |
| 3.4 | **LLM04 — Data Poisoning** | Data validator, integrity checker, trust scorer | 2 days |
| 3.5 | **LLM05 — Output Handling** | XSS scanner, unsafe code detector, output sanitizer | 2 days |
| 3.6 | **LLM06 — Excessive Agency** | Permission auditor, approval workflow, tool monitor | 3 days |
| 3.7 | **LLM07 — Prompt Leakage** | Extraction tester, leakage detector, hardening scorer | 2 days |
| 3.8 | **LLM08 — Vector Security** | Vector DB auditor, isolation validator, embed exposure detector | 2 days |
| 3.9 | **LLM09 — Hallucination** | Hallucination detector, citation validator, confidence scorer | 3 days |
| 3.10 | **LLM10 — Unbounded Consumption** | Token/cost monitor, DoS detector, anomaly detector | 2 days |

## Phase 4: Enterprise Features (Weeks 9-10)

| Step | Task | Details | Effort |
|------|------|---------|--------|
| 4.1 | **Compliance Module** | Framework models, control mapping, compliance engine | 3 days |
| 4.2 | **AI Agent Center** | Agent monitor, permission matrix, activity log | 2 days |
| 4.3 | **Reports Engine** | Report templates (Executive, Technical, OWASP, Risk) | 2 days |
| 4.4 | **Dashboard Enhancement** | Risk summary, OWASP coverage gauge, trend charts | 1 day |

## Phase 5: Frontend Modules (Weeks 11-12)

| Step | Task | Details | Effort |
|------|------|---------|--------|
| 5.1 | **LLM Module Pages** | Create all 10 OWASP module frontend pages with consistent pattern | 4 days |
| 5.2 | **Dashboard Redesign** | AI-specific widgets, risk dashboard, trend charts | 2 days |
| 5.3 | **Compliance UI** | Framework management, control mapping, compliance gauge | 2 days |
| 5.4 | **Agent Center UI** | Agent cards, permission table, activity timeline | 2 days |
| 5.5 | **Report Templates** | Executive, Technical, OWASP Compliance, Risk Assessment | 2 days |

## Phase 6: Testing & Integration (Week 13)

| Step | Task | Details | Effort |
|------|------|---------|--------|
| 6.1 | **Backend Tests** | Unit tests for all detectors, services, and APIs | 2 days |
| 6.2 | **Frontend Tests** | Component tests for all new pages | 1 day |
| 6.3 | **Integration Tests** | End-to-end scan workflow testing | 1 day |
| 6.4 | **Performance Testing** | Load testing for scan engine and API | 1 day |
| 6.5 | **Security Testing** | Penetration testing of the platform itself | 1 day |

## Phase 7: Deployment (Week 14)

| Step | Task | Details | Effort |
|------|------|---------|--------|
| 7.1 | **Docker Setup** | Update Dockerfiles and docker-compose for AI Shield | 1 day |
| 7.2 | **CI/CD Pipeline** | Update deployment pipeline | 1 day |
| 7.3 | **Documentation** | API docs, user guide, admin guide | 1 day |
| 7.4 | **Demo Data** | Seed scripts with realistic AI security data | 1 day |

---

# APPENDIX A: ASM to AI Shield Migration Script Pattern

```python
# scripts/migrate_asm_to_ai_shield.py
"""
Migration script to:
1. Keep all existing Organizations, Users, Auth, RBAC
2. Convert ASM Projects to AI Security Projects
3. Remove ASM-specific scan results (or archive)
4. Initialize new AI Shield modules
5. Create compliance frameworks
"""

from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = 'Migrate ASM data to AI Shield format'

    def handle(self, *args, **options):
        self.stdout.write('Starting ASM → AI Shield Migration...')

        # Step 1: Update project types
        Project.objects.update(project_type='ai_security')
        self.stdout.write('✓ Projects updated')

        # Step 2: Archive old ASM scans
        # Old scans are preserved in an archive status

        # Step 3: Initialize compliance frameworks
        frameworks = [
            {'name': 'OWASP GenAI Security', 'short_name': 'owasp_genai', 'version': '2025'},
            {'name': 'NIST AI RMF', 'short_name': 'nist_ai_rmf', 'version': '1.0'},
            {'name': 'ISO/IEC 42001', 'short_name': 'iso_42001', 'version': '2023'},
            {'name': 'ISO 27001', 'short_name': 'iso_27001', 'version': '2022'},
            {'name': 'MITRE ATLAS', 'short_name': 'mitre_atlas', 'version': '2025'},
        ]
        for fw_data in frameworks:
            ComplianceFramework.objects.get_or_create(**fw_data)
        self.stdout.write('✓ Compliance frameworks initialized')

        # Step 4: Create OWASP module configurations
        # ...

        self.stdout.write(self.style.SUCCESS('Migration complete!'))
```

---

# APPENDIX B: Technology Stack Summary

| Layer | Technology | Action |
|-------|-----------|--------|
| **Backend** | Django + DRF | ✅ Reuse |
| **Database** | PostgreSQL | ✅ Reuse |
| **Cache** | Redis | ✅ Reuse |
| **Auth** | JWT (SimpleJWT) | ✅ Reuse |
| **Task Queue** | Celery | ✅ Reuse |
| **WebSockets** | Django Channels | ✅ Reuse |
| **Frontend** | React/Angular (as existing) | ✅ Reuse |
| **State Mgmt** | Redux/Zustand (as existing) | ✅ Reuse |
| **UI Library** | As existing (MUI/AntD/etc.) | ✅ Reuse |
| **Charts** | Chart.js/Recharts (as existing) | ✅ Reuse |
| **PDF Generation** | WeasyPrint/ReportLab | ✅ Reuse |
| **Container** | Docker | ✅ Reuse |
| **CI/CD** | As existing | ✅ Reuse |
| **New: Detection** | ML + Regex + Heuristic | ➕ New |
| **New: Vector DB** | Chroma/Pinecone/Weaviate client | ➕ New |
| **New: LLM Clients** | OpenAI/Ollama/HuggingFace SDKs | ➕ New |
| **New: SBOM** | CycloneDX library | ➕ New |

---

# APPENDIX C: RBAC Permissions (NEW)

```python
# permissions for AI Shield modules
AI_SHIELD_PERMISSIONS = {
    # AI Assets
    'view_ai_assets': 'Can view AI asset inventory',
    'manage_ai_assets': 'Can create, edit, delete AI assets',
    'discover_models': 'Can run model discovery',

    # AI Security Scans
    'initiate_scan': 'Can start AI security scans',
    'view_scans': 'Can view scan results',
    'cancel_scan': 'Can cancel running scans',

    # OWASP Modules
    'access_llm01': 'Can access Prompt Injection module',
    'access_llm02': 'Can access Sensitive Info module',
    'access_llm03': 'Can access Supply Chain module',
    'access_llm04': 'Can access Data Poisoning module',
    'access_llm05': 'Can access Output Handling module',
    'access_llm06': 'Can access Excessive Agency module',
    'access_llm07': 'Can access Prompt Leakage module',
    'access_llm08': 'Can access Vector Security module',
    'access_llm09': 'Can access Hallucination module',
    'access_llm10': 'Can access Unbounded Consumption module',

    # Compliance
    'view_compliance': 'Can view compliance dashboard',
    'manage_compliance': 'Can manage compliance mappings',

    # Agent Center
    'view_agent_center': 'Can view AI Agent Security Center',
    'manage_agent_permissions': 'Can manage agent permissions',
    'approve_agent_actions': 'Can approve/reject agent actions',

    # Reports
    'generate_reports': 'Can generate and export reports',

    # Findings
    'view_findings': 'Can view security findings',
    'manage_findings': 'Can update finding status, assign',
}
```

---

> **Document Version:** 1.0
> **Prepared for:** GenAI Security Platform — GenAI Security Management Platform
> **Based on:** Original ASM Conversion
> **Date:** June 2026
