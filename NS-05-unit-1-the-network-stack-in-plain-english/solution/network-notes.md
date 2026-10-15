# Reference reasoning: stream, datagrams and application framing

The gate forces the server to observe a prefix before the remaining TCP bytes
are sent. Concatenating every recorded nonempty read recovers the exact stream;
read boundaries need not be message boundaries. EOF follows the sender's write
shutdown. EOF can arrive before the application's newline terminator.

Each UDP receive corresponds to one datagram. The empty first datagram is an
actual received message with a sender, not TCP EOF. A small UDP buffer returns a
prefix with the kernel truncation flag; the missing suffix has been discarded.
The next receive waits for a different datagram. Compare exact hex bytes and the
actual client/worker endpoints. Explain application framing separately from TCP,
IP forwarding and link delivery, using the observed loopback path appropriately.

The executable reference does not grade a learner's diagram or explanation and
does not claim to observe Ethernet frames, packet loss, or a remote network.
