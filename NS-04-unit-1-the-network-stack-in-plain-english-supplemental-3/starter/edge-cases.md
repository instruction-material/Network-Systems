# Queue reasoning cases

Draw the owned receive queue and name the operation responsible for each state.

1. A short consuming diagnostic before the application consumer.
2. A short MSG_PEEK diagnostic before a sufficiently large consuming read.
3. Requested MSG_PEEK versus returned MSG_TRUNC.
4. Three sent datagrams with one consumed by a diagnostic.
5. A bounded empty-queue timeout after earlier successful receives.
6. A second consumer racing this diagnostic: explain why this controlled one-consumer trial does not prove concurrent behavior.

A missing consumer record does not establish network loss when another local receive already consumed that datagram.
