# Setup extension: preserve argument boundaries

This optional investigation extends Setup and Tooling after the required project. It compares a direct argument list with actual Bash execution, then diagnoses a quoting choice. The required artifact is an explanation grounded in the arguments received by an owned worker. Programming the supplied fixture is optional.

Use an ordinary account in an owned Linux lab with Python 3.10 or newer, /bin/sh and /bin/bash. Root execution is refused. On other host systems use a Linux environment with /proc identities. Record interpreter and Bash versions and the issuing context. All files, command names and variable values used by the experiment belong to a temporary private fixture.

## Understand the three boundaries

An application receives an argument vector: an ordered list of separate strings. A space inside one list element remains part of that element when the program is launched directly with an argument list.

Bash first parses the command's structure, then performs expansions. The fixture's variable values contain spaces, a wildcard and a semicolon. For this fixed noninteractive shell command, unquoted expanded words undergo field splitting and filename expansion. Double-quoted expansions preserve each variable's value as a single argument here. The quotes themselves are shell syntax and are removed before the worker receives argv. These behaviors follow the [Bash word-splitting reference](https://www.gnu.org/s/bash/manual/html_node/Word-Splitting.html) and [filename-expansion reference](https://www.gnu.org/s/bash/manual/html_node/Filename-Expansion.html).

A wildcard passed literally and a wildcard expanded into filenames are different data. Expansion uses the current working directory, the actual available files and shell settings. This fixture fixes those conditions using an owned directory and a small C-locale environment, with personal startup variables omitted.

The semicolon in the supplied variable is data after parameter expansion; it is not reparsed into a new command operator. Unquoted expansion can still split its surrounding words. The fixture uses a fixed shell template and does not evaluate variable contents as shell source. The [Bash expansion order](https://www.gnu.org/s/bash/manual/html_node/Shell-Expansions.html) explains where these stages occur.

## Read the expected input

The default desired vector contains exactly three strings:

```text
["two words", "*.txt", "left; right"]
```

The private working directory contains `one.txt` and `two.txt`. A direct argument-list call preserves those three strings. The quoted Bash form also preserves them. The unquoted form passes six strings:

```text
["two", "words", "one.txt", "two.txt", "left;", "right"]
```

These are the fixed command forms inside the apparatus, shown for interpretation. Read their recorded execution rather than invoking the fixture's command name on the host's normal PATH:

```text
course-context "$COURSE_WORDS" "$COURSE_PATTERN" "$COURSE_LITERAL"
course-context $COURSE_WORDS $COURSE_PATTERN $COURSE_LITERAL
```

Keep the actual worker argv beside each command spelling. A printed command line cannot by itself establish where its argument boundaries were.

## Run the unfinished case

Keep `main.py`, `setup_lab.py`, `case.json`, `network-notes.md` and `edge-cases.md` together with the shared `README.md`. The browser workspace can edit, save and export these files; actual Bash and process observations run in the external Linux terminal.

```sh
cd starter
python3 main.py --output first-observation.json
```

A fresh filename is required for every attempt. The program records four stages: direct arguments, quoted shell, unquoted shell and configured mode. The starter sets `quote_arguments` to the JSON boolean `false`. Its configured stage therefore fails the stated three-string goal and exits 78 after retaining observations.

Predict the exact strings and count for all four stages before reading their results. Match each worker's PID, parent PID, UID, hostname, working directory, interpreter and namespaces to its issuing record. The ordinary worker runs in the same inherited namespaces; this exercise creates no new network topology.

Change only `quote_arguments` to `true` and use `quoted-observation.json`. The configured stage now preserves the desired vector. Keep the first failure and correction together. The reference has the completed configuration but the same instrumentation. Successful execution does not supply the independent explanation.

## Transfer the reasoning to a changed fixture

```sh
python3 main.py --alternate --output alternate-observation.json
```

The alternate fixture changes the command name, desired words, wildcard suffix and owned filenames. Its desired vector is:

```text
["changed three words", "*.data", "owned; note"]
```

The actual files are `amber.data` and `blue.data`. Predict why the quoted/direct forms still pass three arguments and why the unquoted form now passes seven. Compare the actual results instead of assuming the default argument count applies. Keep the per-run private paths and file list with that observation.

Explain which differences came from field splitting, which came from filename expansion, and why the semicolon did not launch an extra command. The native validation retains actual exec and directory-change traces to check this boundary.

## Finish the evidence packet

Complete both notebooks with versions, scope, predictions, raw commands and received argument vectors, the corrected JSON boolean, alternate comparison and one unsupported claim. Check executed-target reaping, removal of the private root, unchanged role source and the named parent directory/PATH/context comparison. The report does not establish all possible shell-option behavior or the quoting semantics of a remote shell.

Independent work makes each prediction before opening the received vector. A paced walkthrough can use two or three sessions for direct arguments, the two shell forms, and the changed fixture plus explanation. Keep this optional attempt and its reference separate from the required setup project and the optional command-context transfer.
