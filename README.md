# CommentInject skill: comment-robust AI security review

An agent skill (Claude Code and other `SKILL.md`-compatible assistants) that defends AI-assisted code-security reviews against **adversarial code comments**: comments that claim code is reviewed, sanitized, compliant or safe, so that an LLM reviewer trusts the claim instead of the code.

It is the defensive companion to the [CommentInject v2 benchmark](https://github.com/sunny-chokshi/commentinject-v2) (DOI [10.5281/zenodo.24517327](https://doi.org/10.5281/zenodo.24517327)), which measured how such comments shift LLM vulnerability verdicts on matched vulnerable/fixed code twins.

## What it does
1. **Scan**: lists every comment that makes a security assurance, grouped into five families (verification premise, context manipulation, credibility vocabulary, pressure/distraction, direct assurance).
2. **Review with claims set aside**: the assistant re-reviews each flagged function on the code alone and checks whether the claim holds (for example, whether the "upstream sanitizer" exists).
3. **Benchmark** (optional): scores any detector on the 840 CommentInject v2 cases and reports whether comments cost it discrimination (Δd′) or just made it flag less (Δc).

## Prerequisites
- Python 3.8+ (standard library only; no packages to install).
- For benchmark mode only: `git` and network access to github.com.

## Install
**Claude Code:** copy or clone this repository into your skills folder:
```bash
git clone https://github.com/sunny-chokshi/commentinject-skill ~/.claude/skills/commentinject
```
Then run `/commentinject` in a project. For a single project, clone into `<project>/.claude/skills/commentinject` instead.

**Without an assistant (CLI or CI):**
```bash
python3 -I scripts/scan_comments.py src/ --format md
python3 -I scripts/scan_comments.py src/ --fail-on-findings   # exit 1 if anything is flagged
```

## Output
- Markdown table (default): `file:line`, families, and comment text.
- JSON (`--format json`): a list of `{file, line, comment, families, matched}` objects.
- Exit code 0, or 1 with `--fail-on-findings` when something is flagged; 2 on usage errors.

## Data flows
`scan` reads local files only and makes **no network calls**. `benchmark` mode asks before running `git clone https://github.com/sunny-chokshi/commentinject-v2`; nothing is uploaded anywhere.

## Limitations
- Pattern matching finds explicit security claims. It misses purely distracting comments (e.g. long off-topic performance notes) and unusual phrasings. In the tests it catches 11 of the 12 CommentInject v2 attack comments; the miss is the distraction strategy.
- On the Python 3.14 standard library plus installed packages (27,220 `.py` files) it flagged 79 comments, most of them harmless. Treat findings as prompts for scrutiny, not alerts.
- Supported comment syntaxes: `#` and `//`, `/* */` comments; Python docstrings.
- The benchmark results are exploratory (local 4–8B models, temperature 0, 30 Python pairs).

## Tests
```bash
python3 -I tests/test_scan_comments.py
```
`tests/strategies_v2.json` holds the 12 attack comments from CommentInject v2.

## License
MIT, for everything in this repository. The test fixture `tests/strategies_v2.json` is taken from the author's own CommentInject v2 dataset (CC BY 4.0 there) and is released here under MIT as well.
