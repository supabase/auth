# AI policy

This policy applies to issues, discussions, pull requests, and review comments in this repository.

Reviewer time is the scarce resource in this project. AI tools make it cheap to produce code and text. They do not make it cheap to review. This policy keeps the cost of a contribution on the contributor, not on the reviewer.

## Code

You can use AI tools to write code. You are responsible for the result. Before you open a pull request:

- Read every line of the change. Understand what it does and how it interacts with the rest of Auth.
- Be ready to explain and defend the change in review, without the tool.
- Test the change yourself. Do not rely on the tool's claim that it tested the change.

## Text

Write issues, discussion posts, pull request descriptions, and review replies yourself. Short and clear is better than long and generated. We can close an issue or a pull request when the text is clearly generated and does not show that the author understands the change.

## Disclosure

State in the pull request description which AI tools you used and for what. Disclosure does not count against you. A missing disclosure does.

## Volume

Do not open many pull requests at once. Open one, get it reviewed, learn from the feedback, and then open the next. We can close pull requests from an author who opens many at the same time.

## Why

Auth is security-sensitive software that runs on every Supabase project. A change that looks correct can still be wrong in a way that only shows up at scale or in a specific configuration. A reviewer can only catch that when the author can explain the change and the reasons for it.
