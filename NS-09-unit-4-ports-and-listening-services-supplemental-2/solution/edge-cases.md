# Named reasoning cases

1. Connected but omitted: the same inode appears in the all-socket view and
   disappears from the listening-only view. Explain why disappearance is not
   sufficient evidence of socket closure.
2. Peer selected, no bytes sent yet: identify the report stage before application
   traffic. Explain why a UDP connect call is not a TCP handshake or a reply.
3. Changed payload: change the token and retain a new report. Compare actual
   received bytes instead of inferring an exchange from the inventory alone.
4. Empty final selection: compare the owned inode after closure. Explain why
   unrelated rows or a reused port do not identify the original socket.

Record a prediction, cited observation and limitation for each case.
