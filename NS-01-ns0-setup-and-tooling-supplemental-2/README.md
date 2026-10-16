# Setup transfer: identify the command and its execution context

This optional investigation follows the required Setup and Tooling project. Its question is concrete: which owned command ran, and in which working directory and process context did it run? The prewritten fixture creates two commands with the same name in separate private directories. It changes their search order and the child's working directory, then records actual execution. The task is to diagnose a configuration and explain the evidence, rather than implement a port parser.

Use an ordinary account in an owned Linux lab with Python 3.10 or newer and /bin/sh. Root access is not required and is refused. On macOS or Windows, use a Linux environment with /proc process identities. Record the actual distribution, interpreter version and issuing shell. This exercise neither starts a network service nor measures remote connectivity.

## Concepts needed before the observation

A process has a working directory used to interpret relative paths. A child can receive a different directory without changing the parent's directory. A successful command lookup does not select the directory in which that command runs.

PATH is an ordered list of directories searched for a command name that contains no slash. Two executable files can share a name; changing the order can select a different file. An absolute command path selects that file directly. The owned launcher then uses an absolute Python interpreter and worker path, allowing that particular launcher to work with an empty PATH. This result does not promise that every external program works without PATH.

The fixture records the selected command path, child PID, actual working directory, UID, hostname, interpreter and network/mount namespace identities. The worker reports its own identity after the launcher executes it. A display prompt, a familiar command name or an expected hostname alone is weaker evidence than those actual observations. Namespace strings and numeric UIDs are local context observations, not globally unique host identities or proof of an SSH destination.

The child receives a deliberately small environment with the selected private PATH and a C locale. It does not load personal startup files or inherit credentials. The parent's directory and PATH remain unchanged. The report compares only its named parent fields; it is not a scan of every host setting.

## Read the owned case

The program creates private `alpha bin` and `beta bin` directories, each containing the same command name. Their launchers report different tags. Two work areas are named `north work` and `south work`; their spaces are intentional.

The target for the configured stage is the beta command in the second work area. The starter's `case.json` selects alpha and the first work area. The reference contains the completed configuration. Keep the reference separate until the independent prediction and first observation are recorded.

Keep all five role files together, plus the shared guide: `main.py`, `setup_lab.py`, `case.json`, `network-notes.md`, `edge-cases.md` and `README.md`. The thin launcher is not the implementation exercise. Programming the supplied apparatus is optional and unnecessary for completion.

## Preserve the first result

From the project root:

```sh
cd starter
python3 main.py --output first-observation.json
```

Use a new output filename for every attempt. The unfinished configuration deliberately exits 78 after writing its real observations. Exit 78 here identifies the unmet configured goal; it does not mean that every observed command failed. Retain the program's stdout and the actual JSON file.

Predict each stage before reading it:

| Stage | Command selection | Work area | Observation |
| --- | --- | --- | --- |
| path-alpha | alpha before beta | first | alpha worker |
| path-beta | beta before alpha | first | beta worker |
| cwd-second | beta before alpha | second | beta worker in the changed directory |
| missing-path | empty PATH, bare name | second | launch raises FileNotFoundError |
| absolute-without-path | absolute alpha launcher | second | alpha worker still executes |
| configured | the selected case | selected case | compare with beta in the second area |

For the missing-path stage, Python may create an intermediate process before exec fails. The report records the actual FileNotFoundError and no successful target PID or target exit status. Do not relabel that event as a target program returning 127. The native verification trace separately retains the failed exec attempt.

For each executed target, reconcile the recorded command and resolved path with the worker tag, PID, parent PID, working directory, interpreter and context. Distinguish a lookup observation from proof that the selected target actually ran.

## Correct one variable at a time

Change only `first_tool` to `"beta"` in `case.json`. Keep `work_area` at `"first"` and predict what remains wrong. Run into `tool-corrected.json`. The chosen command is now beta, while the configured directory remains the first area; the configured goal still fails.

Then set `work_area` to `"second"` and use `both-corrected.json`. Both conditions now agree with the stated goal. Explain the independent effect of command search order and working directory. The correction changes configuration only; retain the prewritten worker and launcher.

```sh
python3 main.py --alternate --output alternate-observation.json
```

The alternate run uses a different owned command name and a fresh private root. Predict which observations change and which conclusions remain valid. Refer to paths from that particular report instead of reusing a path from an earlier run.

## Complete the evidence and cleanup review

Complete both notebooks with the issuing context, versions, predictions, actual commands/results, first failures, the one-field correction, completed configuration, alternate comparison and one limit. Check that every executed target was waited for and reaped, the private root was removed, the five role files remained unchanged during each run, and the named parent fields match before and after. Preserve unexpected outcomes.

Independent work predicts before inspecting results. A paced walkthrough can use two or three sessions: command selection; directory and context comparison; then correction, alternate case and explanation. The same saved attempt serves both approaches. A successful exit does not complete the notebook.

The optional argument-boundary extension is a separate investigation. It asks how shell expansion changes argv, rather than repeating this command/directory diagnosis.
