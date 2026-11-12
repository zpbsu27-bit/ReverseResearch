# Protocol reverse workflow

samples -> common/variable bytes -> framing candidates -> endian/length/checksum -> message classes -> state machine -> parser/serializer -> round-trip validation -> dissector

Kaitai/Wireshark/Go/Python output is generated analysis material, not proof. Candidate fields remain candidate until multiple fixtures validate them.

Active replay is a separate effectful step and requires current Engagement scope and a Job.
