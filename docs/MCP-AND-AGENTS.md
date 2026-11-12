# Functions, MCP and agents, and where they fit in Rowanholt

## The three terms

People use these three words loosely, but each names a different layer. One sentence each: a function is something a model can ask to run, MCP is how those functions get packaged and handed to whatever app hosts the model, and an agent is a model running in a loop, deciding which function to call next.

### Functions (tool calling)

A function, or tool, is a piece of your code described to the model by a name, a sentence saying what it does, and a JSON schema for its arguments. The model never runs anything. When it decides a tool would help, it outputs a structured request such as `read_rows(job_id="J42", host="WS01", file="prefetch.csv", limit=50)`. The application hosting the model checks that request, runs the real code, and feeds the result back into the conversation. Then the model carries on.

That gives two properties that matter for Rowanholt:

1. **The application keeps control.** It chooses which tools exist and what each one can reach. It can refuse a call, log it, or ask a human first. The model can only ask for what's on the list.
2. **Tool calling is a skill the model has to have, and the quality varies.** Large hosted models pick tools and fill in arguments reliably. Small local models, including Smith's default `llama3.2:3b`, often pick the wrong tool, invent arguments, or ignore the tools completely.

### MCP (Model Context Protocol)

MCP is a standard for delivering functions. Without it, every host (Claude Desktop, Claude Code, OpenClaw, an IDE) would need its own integration code for every tool. With it, you write one **MCP server** that declares its tools (plus read-only "resources" and prompt templates), and any **MCP host** can connect to it, list the tools and call them. Transport is stdio for a local process, or streamable HTTP for a remote one.

An MCP server is just a process speaking a protocol. It doesn't think. It answers "what tools do you have?" and "run this tool with these arguments". All the intelligence stays in the host's model.

So "should X have an MCP server?" really asks two things: should a model somewhere be able to call X, and should that model be in an app you don't control, like Claude Desktop?

### Agents

An agent is a model in a loop with tools: read the goal, call a tool, look at the result, decide the next step, and repeat until done. What makes it an agent is that the model chooses the steps instead of a program choosing them. Claude Code is an agent. A Claude Code **subagent** (`.claude/agents/*.md`) is a second agent with its own system prompt, its own tool list and a clean context window, which the main session hands one job to.

Agents earn their place when the path isn't known in advance and needs judgement at each step, like investigating, debugging or writing. For work whose steps are known, they're the wrong tool: a script does the same thing faster, the same way every time, and you can audit it.

## How they fit together

| Layer | What it is | Rowanholt example |
|---|---|---|
| Function | One thing a model may ask to run | `read_rows`, `check_indicator`, `ask_offline` |
| MCP server | A process that publishes a set of functions to any MCP host | Smith's MCP server (`rowanholt mcp`, or `/mcp` on a team server) |
| Agent | A model looping over functions towards a goal | Claude Desktop or Claude Code working a case through that server |

Functions are the building blocks, MCP is how they're delivered, and the agent is whatever uses them. You can have functions without MCP (an app's own built-in tools) and an agent without MCP (Claude Code with only its built-in tools). MCP only matters when the functions and the model live in different programs.

## Why "one per component" doesn't fit Rowanholt

Before giving any component its own server or agent, I'd ask two questions: does a model calling this add something a script or a person doesn't already do better, and is it safe for a model to call it? For most of Rowanholt, one or both answers is no.

### Most of Rowanholt is deterministic by design

Elrond is a directed graph of known steps: detect the evidence type, branch by OS, run Volatility, Plaso, RegRipper and YARA as subprocesses, write `cooked/`, map techniques. Every branch is decided by the evidence, not by judgement. Putting an agent in the middle would swap a repeatable pipeline for one that might run a different set of steps each time. In forensics that's the opposite of what you want. Two runs over the same image should give the same output, and the audit log should show a fixed procedure, not a model's choices.

The subprocess boundary and the order-of-volatility logic in Gandalf are there for isolation and defensibility. An agent deciding which artefacts to collect, or in what order, undermines both.

### Some components shouldn't be reachable by a model at all

The roadmap's never-exposed list (`docs/ROADMAP.md`, and the top of `src/smith_mcp/server.py`) exists because these actions change evidence, hosts or shared state, and you can't undo them:

| Component | What a model would be doing | Why not |
|---|---|---|
| Gandalf | Starting acquisitions over SSH or PSRemoting against live hosts | A model with remote execution on a target estate; chain of custody starts here and should start with a person |
| Elrond (control) | Starting, restarting, deleting jobs | Deleting or overwriting output a finding cites, or restarting a job someone is working |
| Pippin (writes) | Importing or deleting threat intelligence | A model poisoning or emptying the indicators every case is matched against |
| Andúril / Aragorn | Recreating containers, changing settings | Interrupting running jobs; admin actions belong with an admin |
| Mordor / the lab | Building VMs, running attack recordings | Dev tooling; a model gains nothing and you get detonations triggered by a prompt |
| `raw/` | Reading evidence as collected | The case browser never reaches it; nor should anything else |

An MCP server for any of these would mostly exist to expose the actions on this list.

### The parts that should be reachable share one server

The useful thing a model can do with Rowanholt is read a finished case and reason about it: which hosts, which rare persistence, which rows match an indicator, what to look at next. That's real judgement work, which is where an agent helps. Smith's MCP server covers it across every component: `list_cases`, `case_overview` and `read_rows` (Elrond's output), `rare_across_hosts` (stacking), `check_indicator` (Pippin), `ask_offline`, `ask_smith`, `case_summary` and `suggestions` (Smith), and `findings`, `report` and `navigator_layer` (the case browser). With `--allow-writes` it adds `flag_lead` and `add_note`, and nothing else that writes; the backend records those as Smith's and refuses anything but a lead. `docs/SMITH.md` has the details.

Splitting that into a server per component would bring three problems:

1. **Several auth paths instead of one.** The single server is a thin client of Rowanholt's API, so every call carries the analyst's `smith-mcp` token and `src/web/backend/auth/access.py` decides what that user can see. Each extra server is another place that check can be skipped.
2. **More to review.** The threat model asks for a review before any MCP tool goes near a live case: the tool list against never-exposed, a test that no tool reaches `raw/`, a test that a user can't reach someone else's job, and no outbound calls (`tests/unit/test_smith_mcp.py`). That's one review for one server, or one per component.
3. **A worse experience for the model.** A host connected to six small servers sees six sets of overlapping tool descriptions and has to work out which `findings` is which. One server with one set of instructions ("start from a job id, cite file and row, a lead is not a verdict") works better.

`.claude/CLAUDE.md` records the rule: one MCP server (mcp 2's `MCPServer`, formerly FastMCP), every Smith capability registered through it, no parallel registration.

### Agents inside Rowanholt, and Smith's model

You could have Smith call functions itself, with Ollama's tool calling instead of the fixed offline questions. With `llama3.2:3b` that would be less reliable than what exists now. The offline answers are fixed functions that a person picks from a list, so they always return the right rows. A 3B model choosing tools would sometimes choose wrong, and a wrong answer that looks confident is worse than none in a case. It becomes worth revisiting when Smith runs on a model that's actually good at tool calling. Even then, most of the gain already came from row citations: Smith's answers list the rows they cite, each with ⚑ to flag it, and drop any tag the model made up.

## Where agents do fit: building Rowanholt

Claude Code subagents are a different matter, because they're for development, not for running cases. A subagent is just a markdown file with a prompt and a tool list. It costs nothing at runtime and never sees a case. It's worth having where a task repeats and has a fixed convention that otherwise gets re-explained each session:

| Candidate subagent | The convention it holds |
|---|---|
| Artefact-parser author | stdlib module in `process/extractions/` → OS router → `cooked/<name>.csv` → `_record_techniques` → `is_extra_artefact` in `process/extra_artefacts.py` → unit test |
| Lab runner | `lab.sh` targets, `verify-expected.py` against `expected.json`, never editing `lab.sh` mid-run, `tests/docs/BUGS.md` for what breaks |
| Gandalf cross-collector reviewer | A collection change lands in bash, Python and PowerShell alike, read-only, hashed into `log.meta` |

None of these is urgent. The sensible trigger is the next time you do one of these jobs and notice you're explaining the same steps again.

## Summary of the position

| Question | Answer |
|---|---|
| An MCP server for Rowanholt? | Yes: one, Smith's, read-only unless started with `--allow-writes` (leads and notes only); built, over stdio and streamable HTTP |
| One MCP server per component? | No: duplicated auth, multiple reviews, mostly exposing never-exposed actions |
| Agents inside the pipeline (Gandalf, Elrond)? | No: deterministic and auditable by design |
| Smith calling functions through Ollama? | Not on a 3B model; revisit with a stronger local model |
| Claude Code subagents for development? | Optional, cheap, add when a repeated task calls for one |
