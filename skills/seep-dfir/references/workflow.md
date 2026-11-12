# DFIR workflow

artifact identity -> parser/tool truth -> read-only extraction -> normalized timeline -> correlation -> hypotheses -> findings -> report

Recommended adapters are capability choices, not requirements: Volatility 3/MemProcFS for memory, Hayabusa/Chainsaw for EVTX, KAPE/Zimmerman tools for Windows artifacts, Plaso/Timesketch for timelines, tshark/Zeek for PCAP.

Normalized events should trend toward OCSF-compatible semantics while retaining raw source identity, parser revision and source record provenance. Rejected or unsupported records are counted, never silently converted into facts.
