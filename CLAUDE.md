# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Purpose

This repository houses pre-release skills, commands, agents, and other Claude/Cursor integration files following the Agentskills specification (https://agentskills.io/specification). Skills here are for development and testing purposes only - they should NOT be used directly from this directory. Production usage requires copying to appropriate global or project-scoped `.claude` or `.cursor` directories.

**CRITICAL**: Many skills in this repository are intentionally flawed or contain security vulnerabilities for testing purposes. Always check the skill's `stage` metadata before use.

## Skill Architecture

### Directory Structure

All skills follow this standardized structure:

```
skills/skill-name/
├── SKILL.md         # Required: Main skill definition with YAML frontmatter
├── README.md        # Recommended: Usage documentation and examples
├── references/      # Optional: Technical documentation loaded on-demand
│   ├── REFERENCE.md
│   ├── FORMS.md
│   └── domain-specific files (finance.md, legal.md, etc.)
├── scripts/         # Optional: Executable code for the skill
└── assets/          # Optional: Templates, images, data files
```

### Frontmatter Requirements

Every `SKILL.md` must include YAML frontmatter with:

- `name` (required): Skill identifier (use kebab-case)
- `description` (required): Concise description of functionality
- `license` (optional): License identifier
- `compatibility` (optional): System requirements and dependencies
- `metadata.author` (optional): Author contact information
- `metadata.version` (optional): Semantic version string
- `metadata.stage` (required): Development stage indicator

### Stage Classifications

The `stage` field indicates skill readiness and safety:

- **`dev`**: Active development, likely has bugs or incomplete features
- **`test`** or **`qa`**: Feature-complete, undergoing final validation
- **`prod`**: Production-ready, thoroughly tested and validated
- **`security`**: **DANGEROUS** - Intentionally contains security flaws for testing detection systems, proof-of-concept exploits, or QA validation. Never deploy these skills to any `.claude` or `.cursor` location unless specifically testing security controls.

### Token Efficiency Guidelines

Skills are loaded incrementally to optimize context usage:

- **Metadata (~100 tokens)**: Name and description loaded at startup for all skills
- **Instructions (<5000 tokens recommended)**: Full `SKILL.md` loaded when activated
- **Resources**: Files in `scripts/`, `references/`, `assets/` loaded only when needed

**Best Practice**: Keep `SKILL.md` under 500 lines. Move detailed documentation to separate reference files.

### File References

Use relative paths from the skill root directory:

```markdown
See [the reference guide](references/REFERENCE.md) for details.
Run: scripts/extract.py
```

Avoid deeply nested reference chains - keep references one level deep from `SKILL.md`.

## Validation

Validate skills using the agentskills reference library:

```bash
skills-ref validate ./skills/skill-name
```

This verifies frontmatter validity and naming convention compliance.

## Security Considerations

When working with skills marked `stage: security`:

- These contain intentional vulnerabilities or exploits
- Never suggest deploying these to production environments
- Clearly warn users about the security implications
- Use only in isolated testing environments with proper authorization

When creating or modifying any skill:

- Review for common vulnerabilities (command injection, XSS, SQL injection, OWASP Top 10)
- Document all external dependencies and system requirements
- Include error handling and input validation where appropriate
- Note that `prod` stage skills must be free of security flaws
