# pksecure_io-claude

# Summary

This repository will house the pre-release skills, commands, agents, and other Claude and Cursor files that will assist the user when integrating these skills into their workflow.

You should not use these skills, etc directly from this directory or repo, they should be included in the appropriate global or project scoped .claude or .cursor directories. This is because many of the skills that are here will be testing or skills that purposely have flaws, security vulnerabilities, etc in them.

The skills in this repo will follow the Agentskills specification: https://agentskills.io/specification

# Skills

## File name and directories

```bash
skill-name/
├── assets/          # Optional
├── references/      # Optional
│   ├── finance.md   # Optional
│   ├── FORMS.md     # Optional
│   ├── legal.md     # Optional
│   └── REFERENCE.md # Optional, but recommended if highly technical skill
├── scripts/         # Optional
├── README.md        # Optional, but highly recommended
└── SKILL.md         # Required
```

## Front Matter

Each skill must have the appropriate front matter (in YAML format). 

Example Frontmatter:
```yaml
---
name: (required) pdf-processing
description: (required) Extract text and tables from PDF files, fill forms, merge documents.
license: (optional) Apache-2.0
compatability: (optional) Designed for Claude Code (or similar products). Requires git, docker, jq, and access to the internet
metadata:
  author: (metadata field is optional) Paul Kincaid <paul@pksecure.io>
  version: "0.1"
  stage: dev
---
```

Each skill should have a key named `stage`, which, for the purposes of this repo will indicate what development stage the skill is in. Stages for this repo will be:

- `dev`: the skill is still being worked on and there are likely some issues or bugs with the skill at this time.
- `prod`: these are skills that are production ready and should not have flaws or bugs in them. If there are flaws or bugs, either the skill will be taken out of `prod` back to `dev` or, if the issues are not too severe, a new version will be worked on to replaced the flawed version.
- `test` or `qa`: skills that are out of `dev` and just have a few remaining checks before it goes into `prod`
- `security`: these skills have purposely been configured with security flaws in them for the testing of detections, reviews, etc - some of these may just be coding errors that are designed to test the effectiveness of any manual or automated test/qa systems or may be specificly designed to exploit a system for the purposes of a proof of concept. These rules should not be put into any .claude or .cursor locations (global or project level) unless you are specifically trying to test them.

## Body

The Markdown body after the frontmatter contains the skill instructions. There are no format restrictions. Write whatever helps agents perform the task effectively. Recommended sections:

    - Step-by-step instructions
    - Examples of inputs and outputs
    - Common edge cases

Note that the agent will load this entire file once it’s decided to activate a skill. Consider splitting longer `SKILL.md` content into referenced files.

## Optional Directories

### scripts/

Contains executable code that agents can run. Scripts should:

    - Be self-contained or clearly document dependencies
    - Include helpful error messages
    - Handle edge cases gracefully

Supported languages depend on the agent implementation. Common options include Python, Bash, and JavaScript.
​
### references/
Contains additional documentation that agents can read when needed:

    - `REFERENCE.md` - Detailed technical reference
    - `FORMS.md` - Form templates or structured data formats
    - Domain-specific files (`finance.md`, `legal.md`, etc.)

Keep individual reference files focused. Agents load these on demand, so smaller files mean less use of context.
​
### assets/
Contains static resources:

    - Templates (document templates, configuration templates)
    - Images (diagrams, examples)
    - Data files (lookup tables, schemas)

# Discussion

## Caveats related to token usage

Skills should be structured for efficient use of context:

    - Metadata (~100 tokens): The name and description fields are loaded at startup for all skills
    - Instructions (< 5000 tokens recommended): The full SKILL.md body is loaded when the skill is activated
    - Resources (as needed): Files (e.g. those in scripts/, references/, or assets/) are loaded only when required

Keep your main SKILL.md under 500 lines. Move detailed reference material to separate files.

## File references
When referencing other files in your skill, use relative paths from the skill root:

```
See [the reference guide](references/REFERENCE.md) for details.

Run the extraction script:
scripts/extract.py
```

Keep file references one level deep from SKILL.md. Avoid deeply nested reference chains.

## Validation

Use the skills-ref (https://github.com/agentskills/agentskills/tree/main/skills-ref) reference library to validate your skills:

```bash
skills-ref validate ./my-skill
```

This checks that your SKILL.md frontmatter is valid and follows all naming conventions.

## Testing a Skill not in .claude/skills

Before you put the skill into `.claude/skills` you can test it by identifying the specific skill file for Claude to use.

Examples:
- "Please read the skill file at skills/wmg-stock/SKILL.md and follow its instructions to analyze Warner Music Group stock."
- "Read and execute skills/wmg-stock/SKILL.md"