# Setup evidence notebook

## Boundary and issuing context
Record the owned Linux environment, distribution, interpreter and shell versions,
ordinary UID, hostname, working directory and namespace observations.
Distinguish a display prompt from an observed execution context.

## Predictions before observation
Record the predicted command, directory and received arguments for every stage.
Keep the default and alternate predictions separate.

## Actual observations
Retain the exact command, output filename, status and unedited JSON report.
Connect each successful worker PID and context to the recorded launch.
Keep failed lookup or unmet configuration goals separate from successful stages.

## Correction and changed case
Preserve the first failure, the smallest configuration change, intermediate
result when applicable, final retest and alternate observation. Explain each
changed condition instead of replacing the first report.

## Cleanup and limits
Record target reaping, removal of the private root and the named parent-field
comparison. Name a conclusion the observations cannot establish and the next
authorized check that could disprove the current explanation.

## Independent explanation or paced walkthrough
Explain the same evidence without opening the reference first. A walkthrough
pauses at predictions, actual execution, correction and cleanup. Program success
does not complete this notebook.
