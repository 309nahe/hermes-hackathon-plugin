"""Tool JSON schemas for RookGuard (rookguard).

RookGuard keeps an inventory of the host's packages, scans it against
cve.now, reports prioritized findings with fixed versions, and applies
user-approved upgrades. Tagline: track, scan, fix.

Schemas follow the Hermes plugin contract: each one is the dict passed to
``ctx.register_tool(..., schema=...)`` and read by the LLM. Handlers return a
JSON string (including on error) and never raise.
"""

ROOKGUARD_INVENTORY_SCHEMA = {
    "name": "rookguard_inventory",
    "description": (
        "Snapshot the packages installed on the host (dpkg, pip, npm) and store "
        "them in RookGuard's durable inventory. Use when the user asks what is "
        "installed or before a scan. Combines a baseline snapshot with the "
        "deltas tracked by the post_tool_call hook."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "ecosystems": {
                "type": "array",
                "items": {"type": "string", "enum": ["dpkg", "pip", "npm"]},
                "description": (
                    "Package ecosystems to inventory. Defaults to all three. "
                    "v1 supports Debian/Ubuntu (dpkg), pip and npm only."
                ),
                "default": ["dpkg", "pip", "npm"],
                "uniqueItems": True,
            },
        },
        "required": [],
        "additionalProperties": False,
    },
}

ROOKGUARD_SCAN_SCHEMA = {
    "name": "rookguard_scan",
    "description": (
        "Scan the inventoried packages for known vulnerabilities through the "
        "cve.now check_stack API and store the findings (CVE IDs, affected "
        "versions and fixed versions). Use after rookguard_inventory or when the "
        "user asks whether the host is vulnerable. Returns a short summary; call "
        "rookguard_status for the grouped report."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "ecosystems": {
                "type": "array",
                "items": {"type": "string", "enum": ["dpkg", "pip", "npm"]},
                "description": (
                    "Restrict the scan to these ecosystems. Defaults to every "
                    "ecosystem present in the inventory."
                ),
                "uniqueItems": True,
            },
            "min_severity": {
                "type": "string",
                "enum": ["low", "medium", "high", "critical"],
                "description": (
                    "Only report findings at or above this severity. Defaults to "
                    "'low', which reports everything."
                ),
                "default": "low",
            },
        },
        "required": [],
        "additionalProperties": False,
    },
}

ROOKGUARD_STATUS_SCHEMA = {
    "name": "rookguard_status",
    "description": (
        "Report RookGuard findings grouped by severity (critical, high, medium, "
        "low), with CVE IDs, affected package versions and the fixed versions "
        "to upgrade to. Use to tell the user what needs attention and what to "
        "fix next. Read-only: it never changes the host."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "severity": {
                "type": "string",
                "enum": ["low", "medium", "high", "critical"],
                "description": (
                    "Show only findings at or above this severity. Omit to show "
                    "the full grouped report."
                ),
            },
            "ecosystem": {
                "type": "string",
                "enum": ["dpkg", "pip", "npm"],
                "description": "Show only findings for this ecosystem.",
            },
            "include_fixed": {
                "type": "boolean",
                "description": (
                    "Also list findings that already have a package upgrade "
                    "applied. Defaults to false (open findings only)."
                ),
                "default": False,
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of findings to return (1-500).",
                "minimum": 1,
                "maximum": 500,
                "default": 50,
            },
        },
        "required": [],
        "additionalProperties": False,
    },
}

ROOKGUARD_FIX_SCHEMA = {
    "name": "rookguard_fix",
    "description": (
        "Upgrade one package, or every approved package, to the fixed versions "
        "reported by rookguard_status, then record the outcome in the finding. "
        "Runs the ecosystem upgrade command (apt-get, pip or npm) with sudo by "
        "default and requires the user's explicit approval for each package or "
        "bulk run; RookGuard never auto-approves upgrades. Provide either "
        "'package' or 'all'."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "package": {
                "type": "string",
                "description": (
                    "Name of the package to upgrade, as reported by "
                    "rookguard_status."
                ),
                "minLength": 1,
            },
            "all": {
                "type": "boolean",
                "description": (
                    "Upgrade every approved package that has an available fix. "
                    "Cannot be combined with 'package'."
                ),
                "default": False,
            },
            "ecosystem": {
                "type": "string",
                "enum": ["dpkg", "pip", "npm"],
                "description": (
                    "Ecosystem that owns the package. Inferred from the "
                    "inventory when omitted."
                ),
            },
        },
        "required": [],
        "anyOf": [
            {"required": ["package"]},
            {"properties": {"all": {"const": True}}, "required": ["all"]},
        ],
        "additionalProperties": False,
    },
}

ROOKGUARD_SCHEMAS = (
    ROOKGUARD_INVENTORY_SCHEMA,
    ROOKGUARD_SCAN_SCHEMA,
    ROOKGUARD_STATUS_SCHEMA,
    ROOKGUARD_FIX_SCHEMA,
)

__all__ = [
    "ROOKGUARD_INVENTORY_SCHEMA",
    "ROOKGUARD_SCAN_SCHEMA",
    "ROOKGUARD_STATUS_SCHEMA",
    "ROOKGUARD_FIX_SCHEMA",
    "ROOKGUARD_SCHEMAS",
]
