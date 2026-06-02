# resolv / NSS config-line parsers — pass 5 (frankenlibc-core)

Worker: rch AMD EPYC, bench profile, custom ns/op harness (resolv_parsers_bench).

| bench | p50 ns | mean ns | note |
|-------|--------|---------|------|
| parse_protocols_line_typical | 99.3 | 101.0 | single line, owned-Vec fields |
| parse_hosts_line_typical | 114.4 | 116.5 | addr + Vec<Vec<u8>> hostnames |
| parse_aliases_line_typical | 116.8 | 119.7 | |
| parse_services_line_typical | 134.0 | 136.3 | |
| parse_networks_line_typical | 137.8 | 136.9 | |
| **parse_netgroup_triples_match** | **603.0** | 612.7 | parses a multi-line block; ~100-150ns/line + per-triple temp Vec |

## Hypothesis ledger
```
H-netgroup-tempvec  extract_triples_into allocates a throwaway Vec<&[u8]> per triple : SUPPORTS (filed P3)
  netgroup/mod.rs extract_triples_into: `let parts: Vec<&[u8]> = inner.split(b',').collect();`
  then reads only parts.first()/get(1)/get(2). The heap Vec is pure waste — replace with a
  `let mut it = inner.split(b','); let host=it.next(); user=it.next(); domain=it.next();` iterator
  (zero alloc). One temp-Vec heap alloc removed per triple. Bead: bd-osbo8c.

H-line-parser-owned-fields  line parsers return owned Vec<Vec<u8>> (per-field to_vec) : OBSERVATION (not filed)
  parse_hosts/services/protocols/networks/aliases each allocate owned Vec field copies
  (resolv/mod.rs parse_hosts_line: `fields.map(|f| f.to_vec()).collect()`). At ~100-140ns the cost
  is part allocation, part real validation (IP/number parsing). Returning slices borrowed from the
  input line (&[u8] lifetime-tied to caller buffer) would cut the allocation, but it is an API/
  lifetime change with caller impact and weaker EV than the egregious cases (printf bd-yftnsz,
  memcmp bd-6ypsli). Left as a documented opportunity, not a bead, to avoid low-EV noise.

H-netgroup-anomaly  netgroup 603ns is an algorithmic anomaly : REJECTS
  It parses the whole multi-line NETGROUP_CONTENT block, not one line; per-line cost (~100-150ns)
  is in line with the single-line parsers. The temp-Vec (above) is the only clear inefficiency.
```

## Cross-pass note
resolv/NSS parsers are reasonable; no dramatic hotspot. The one clean, zero-risk win is the
per-triple throwaway Vec in netgroup. The recurring per-call-allocation theme is already
represented by bd-yftnsz (printf) at higher EV.
