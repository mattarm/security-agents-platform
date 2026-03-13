"""ISO/IEC 42001:2023 — AI Management System, Annex A controls (A.2–A.10)."""

from security_agents.core.grc_models import Control, Framework
from security_agents.core.grc_frameworks import _register

_CONTROLS = [
    # =========================================================================
    # A.2 — AI Policies
    # =========================================================================
    Control(id="A.2.2", framework_id="iso_42001_2023", parent_id="A.2", title="AI policy",
            description="An AI policy appropriate to the purpose of the organization shall be established."),
    Control(id="A.2.3", framework_id="iso_42001_2023", parent_id="A.2", title="Internal use AI policy",
            description="A policy on internal AI use shall address responsible AI development and deployment."),
    Control(id="A.2.4", framework_id="iso_42001_2023", parent_id="A.2", title="AI system inventory",
            description="An inventory of AI systems shall be maintained."),

    # =========================================================================
    # A.3 — Internal Organization
    # =========================================================================
    Control(id="A.3.2", framework_id="iso_42001_2023", parent_id="A.3", title="Roles and responsibilities",
            description="Roles and responsibilities for AI system development and operation shall be defined."),
    Control(id="A.3.3", framework_id="iso_42001_2023", parent_id="A.3", title="Reporting relationships",
            description="Reporting relationships shall be established to ensure effective oversight of AI systems."),
    Control(id="A.3.4", framework_id="iso_42001_2023", parent_id="A.3", title="Competence requirements",
            description="Competence requirements for AI roles shall be determined and maintained."),

    # =========================================================================
    # A.4 — Resources for AI Systems
    # =========================================================================
    Control(id="A.4.2", framework_id="iso_42001_2023", parent_id="A.4", title="Resource allocation",
            description="Resources for AI system lifecycle management shall be identified and allocated."),
    Control(id="A.4.3", framework_id="iso_42001_2023", parent_id="A.4", title="Computing and data resources",
            description="Computing infrastructure and data resources shall be adequate for AI system requirements."),
    Control(id="A.4.4", framework_id="iso_42001_2023", parent_id="A.4", title="Tooling and environments",
            description="Tools and environments for AI development shall be maintained and secured."),

    # =========================================================================
    # A.5 — Assessing AI System Impact
    # =========================================================================
    Control(id="A.5.2", framework_id="iso_42001_2023", parent_id="A.5", title="AI impact assessment",
            description="Impact assessments shall be conducted for AI systems identifying affected parties and potential harms."),
    Control(id="A.5.3", framework_id="iso_42001_2023", parent_id="A.5", title="Impact assessment scope",
            description="The scope of AI impact assessment shall consider the full lifecycle and all stakeholders."),
    Control(id="A.5.4", framework_id="iso_42001_2023", parent_id="A.5", title="Documenting impacts",
            description="Results of impact assessments shall be documented and maintained."),

    # =========================================================================
    # A.6 — AI System Lifecycle
    # =========================================================================
    Control(id="A.6.2", framework_id="iso_42001_2023", parent_id="A.6", title="AI system lifecycle processes",
            description="Processes shall be established for each stage of the AI system lifecycle."),
    Control(id="A.6.3", framework_id="iso_42001_2023", parent_id="A.6", title="Design and development",
            description="AI systems shall be designed and developed with consideration of responsible AI principles."),
    Control(id="A.6.4", framework_id="iso_42001_2023", parent_id="A.6", title="Testing and validation",
            description="AI systems shall be tested and validated before deployment."),
    Control(id="A.6.5", framework_id="iso_42001_2023", parent_id="A.6", title="Deployment",
            description="AI system deployment shall follow established criteria and procedures."),
    Control(id="A.6.6", framework_id="iso_42001_2023", parent_id="A.6", title="Operation and monitoring",
            description="AI systems in operation shall be continuously monitored for performance and compliance."),
    Control(id="A.6.7", framework_id="iso_42001_2023", parent_id="A.6", title="Retirement and decommissioning",
            description="Procedures shall be established for AI system retirement."),

    # =========================================================================
    # A.7 — Data for AI Systems
    # =========================================================================
    Control(id="A.7.2", framework_id="iso_42001_2023", parent_id="A.7", title="Data quality",
            description="Data quality requirements shall be defined and managed for AI systems."),
    Control(id="A.7.3", framework_id="iso_42001_2023", parent_id="A.7", title="Data provenance",
            description="The provenance of data used in AI systems shall be documented."),
    Control(id="A.7.4", framework_id="iso_42001_2023", parent_id="A.7", title="Data preparation",
            description="Data preparation processes shall be documented and reproducible."),
    Control(id="A.7.5", framework_id="iso_42001_2023", parent_id="A.7", title="Bias assessment",
            description="Data shall be assessed for bias that may affect AI system outcomes."),

    # =========================================================================
    # A.8 — Technology and AI Models
    # =========================================================================
    Control(id="A.8.2", framework_id="iso_42001_2023", parent_id="A.8", title="Model selection",
            description="AI model selection shall consider fitness for purpose, explainability, and risk."),
    Control(id="A.8.3", framework_id="iso_42001_2023", parent_id="A.8", title="Model training",
            description="AI model training shall follow documented procedures with version control."),
    Control(id="A.8.4", framework_id="iso_42001_2023", parent_id="A.8", title="Model evaluation",
            description="AI models shall be evaluated using appropriate metrics and datasets."),
    Control(id="A.8.5", framework_id="iso_42001_2023", parent_id="A.8", title="Model interpretability",
            description="Appropriate levels of model interpretability shall be determined and achieved."),
    Control(id="A.8.6", framework_id="iso_42001_2023", parent_id="A.8", title="AI model documentation",
            description="AI models shall be documented including architecture, training data, and limitations."),

    # =========================================================================
    # A.9 — Human Oversight
    # =========================================================================
    Control(id="A.9.2", framework_id="iso_42001_2023", parent_id="A.9", title="Human oversight approach",
            description="An approach to human oversight shall be determined based on AI system risk level."),
    Control(id="A.9.3", framework_id="iso_42001_2023", parent_id="A.9", title="Override capability",
            description="Capability to override AI system decisions shall be maintained where appropriate."),
    Control(id="A.9.4", framework_id="iso_42001_2023", parent_id="A.9", title="Monitoring of AI decisions",
            description="AI system decisions shall be monitored for accuracy, fairness, and drift."),
    Control(id="A.9.5", framework_id="iso_42001_2023", parent_id="A.9", title="Escalation procedures",
            description="Procedures for escalating AI system issues to human decision-makers shall be established."),

    # =========================================================================
    # A.10 — AI System Operation
    # =========================================================================
    Control(id="A.10.2", framework_id="iso_42001_2023", parent_id="A.10", title="Transparency",
            description="The use of AI systems shall be transparent to affected stakeholders."),
    Control(id="A.10.3", framework_id="iso_42001_2023", parent_id="A.10", title="Communication with users",
            description="Users of AI systems shall be informed about the nature and limitations of AI involvement."),
    Control(id="A.10.4", framework_id="iso_42001_2023", parent_id="A.10", title="Third-party AI provision",
            description="Requirements for third-party AI systems and services shall be established."),
    Control(id="A.10.5", framework_id="iso_42001_2023", parent_id="A.10", title="Incident management",
            description="Processes for managing AI-related incidents shall be established."),
]

ISO_42001_2023 = Framework(
    id="iso_42001_2023",
    name="ISO/IEC 42001:2023 AI Management Systems",
    version="2023",
    structure_type="hierarchical",
    controls=_CONTROLS,
)

_register(ISO_42001_2023)
