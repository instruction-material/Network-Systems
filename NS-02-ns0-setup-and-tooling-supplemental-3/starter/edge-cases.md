# Constructed argument-boundary cases

These are supplied reasoning questions. Keep them separate from actual fixture
results and do not run additional commands against remote services.

## Case A: the printed command looks unchanged
A log prints spaces but omits argv boundaries. State what extra evidence is
needed to distinguish one string containing spaces from several arguments.
Use the owned worker's actual JSON argument list for the measured comparison.

## Case B: a pattern becomes a file list
Explain which current directory and file inventory apply to an unquoted pattern.
Predict the default and alternate expansions before reading either result.
Different files or shell options can change that outcome.

## Case C: a semicolon came from a variable
Distinguish original command syntax from variable data after expansion. Explain
the actual literal semicolon argument and why the owned trace contains no extra
command execution. This fixed template does not evaluate variable text as code.

## Required comparison
Keep direct, quoted, unquoted and configured argument vectors beside each other.
Identify field splitting and filename expansion separately. Record the corrected
JSON boolean, changed fixture, process context, cleanup and one remaining limit.
