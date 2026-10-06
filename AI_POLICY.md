# AI Usage Policy

This policy applies to issues, discussions, pull requests, and review comments in this repository.

We love AI and use it a lot. However, reviewer time is a scarce resource in this project. AI tools make it cheap to produce output, but they do not make it cheap to review.

## Code

You can use AI tools to write code, but you are responsible for the code in your PR.

Before you open a pull request:

- Read every line of the change. Understand what it does and how it interacts with the rest of Auth.
- Be ready to explain and defend the change in review.
- Test the change yourself. Do not rely on the tool's claim that it tested the change.

## Text

We do not allow AI-generated text in places where human-to-human communication is expected.

Write issues, discussion posts, pull request descriptions, and review replies yourself. Using AI to proofread, tighten, and restructure your own writing is fine. We will close PRs when we believe the work was not deeply understood by the human authoring it.


## Disclosure

State in the pull request description which AI tools you used and for what. 

Include:

- what the tool did (drafted code, refactor, tests, docs, investigation, etc.)
- what you personally verified (and how)

Disclosure won't be counted against you, but undisclosed AI usage may result in the PR being closed.


## Volume

Do not open many pull requests at once. Open one, get it reviewed, learn from the feedback, and then open the next (following the standard process of Discussion->Issue->PR). We may close pull requests from an author who opens many at the same time.

## Why

Auth is security-sensitive software that runs on a vast number of Supabase projects around the world. A change that looks correct could still be wrong in a way that only shows up at scale or in a specific scenario. We require that each code author deeply understands the work they're submitting, and can explain it to give the reviewers the best chance to identify issues.

Supabase engineers follow the same rules for AI usage. This policy applies them to everyone who contributes to Auth.
