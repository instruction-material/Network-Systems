# Framing reasoning cases

For each case name the application boundary, evidence needed and appropriate decoder response. The provided trial exercises valid records with a deliberately partial first observation.

1. One received byte of a four-byte length prefix.
2. A complete advertised length with an incomplete payload at EOF.
3. Two complete records in one observed byte sequence.
4. A UTF-8 payload whose byte length differs from its visible character count.
5. A claimed size over the documented 128-byte bound.
6. A long-lived connection with a complete record before EOF.

Do not label the number of socket reads as a packet count. Distinguish reasoning cases from malformed inputs actually run.
