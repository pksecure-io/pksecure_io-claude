# skill-name Documentation

```
For actual skills that are created, you should keep the headers in this document, but delete all of the explanation matter and enter you own descriptions, examples, etc. (everything contained in ``` ``` sections are the instructions for filling out the README.md for the skill).

For those things that are not used, such as assets/, references/ or scripts/ - would still recommend keeping those headers to maintain consistency between all skills, but just put something like "Scripts are not used in this skill"

Replace "skill-name" above with the actual name of the skill

Use a `README.md` to further discuss and document the skill, including example prompts, usage of the contents `scripts/` and `assets/`.

The technical details could also be included in the `references/REFERENCE.md` file.
```

# External Documentation and Resources

```
You can use this file to also document any external resources or references that could better help the user when executing the skill.

For example, if you have a skill to run a STRIDE Threat Model - provide a link to the official STRIDE documentation and perhaps a good blog post or two that describe STRIDE in detail to help the user learn the benefits of STRIDE
```

# Usage

## Example prompts

```
- "Show me x, y, z"
```

## Key Assets

```
Optional folder and files

Identify any key assets and potentially where those assets were from, how generated or specifics on the files.

For example, if you have a company logo as an asset - specify the size, type of image, tranparency, etc so other users can update to their specific use cases.

For things like datafiles - specify the generic formatting, fields, etc that are required and used by the rest of the skill and how to generate that lookup if you are using common tools.
```

## scripts/

```
Optional folder and files

Ensure you have clearly identified any requirements (for example, through a Python `requirements.txt` or a `go.mod`) in this directory. Also, ensure there are instructions for using virtual environments for Python if the user wants to have this self contained.
```

## References

```
Optional folder and files
```

### REFERENCE.md

```
Detailed technical reference
```

### FORMS.md

```
Form templates or structured data formats
```

### Domain specific files

```
Files that are unique to a specific domain that could be used for the skill - thus potentially allowing separate responses based on what the user is asking about. For example, `finance.md` or `legal.md`
```