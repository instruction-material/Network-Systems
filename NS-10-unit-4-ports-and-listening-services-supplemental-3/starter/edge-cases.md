# Named reasoning cases

1. Two owners, one listener: compare the parent/child descriptor links and one
   listening row. Explain how counting PIDs can overcount sockets.
2. Parent closes first: identify the remaining owner and successful child reply.
   Explain why one process closing its descriptor does not close every reference.
3. Child exits: reconcile its exit status with the final listening selection.
   Explain why a TIME-WAIT row, if present, is not a remaining listener.
4. Later reuse: explain why PID/inode values from a completed run are not durable
   identities for an unrelated later inventory or another network namespace.

Record a prediction, cited observation and limitation for each case.
