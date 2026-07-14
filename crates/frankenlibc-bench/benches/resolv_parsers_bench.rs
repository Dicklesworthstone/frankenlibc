//! /etc-database parser cost-surface benchmarks (bd-ua2x8).
//!
//! `harness = false` binary in the same minimal-overhead p50/p95/p99
//! style as `errno_bench`. Maps the runtime cost of each parser
//! freshly lifted to `frankenlibc-core` by the porting-to-rust epic
//! plus the two pre-existing siblings (`parse_hosts_line`,
//! `parse_services_line`). Output rows are consumed by
//! `perf_gate.sh`; future regressions caused by adding logging,
//! UTF-8 decode, or extra allocation on the parser hot path become
//! visible via the gate.
//!
//! No host-glibc dependency — pure FrankenLibC core.

use std::hint::black_box;
use std::time::{Duration, Instant};

use frankenlibc_core::aliases;
use frankenlibc_core::grp;
use frankenlibc_core::netgroup;
use frankenlibc_core::proc_maps;
use frankenlibc_core::pwd;
use frankenlibc_core::resolv;
use frankenlibc_core::rpc;

const SAMPLES: usize = 100;
const ITERS_PER_SAMPLE: u64 = 10_000;

struct BenchStats {
    samples_ns_per_op: Vec<f64>,
    total_iters: u64,
    total_ns: u128,
}

impl BenchStats {
    fn record(&mut self, iters: u64, dur: Duration) {
        let ns = dur.as_nanos();
        self.total_iters = self.total_iters.saturating_add(iters);
        self.total_ns = self.total_ns.saturating_add(ns);
        self.samples_ns_per_op.push(ns as f64 / iters as f64);
    }

    fn report(&self, mode_label: &str, bench_label: &str) {
        let mut samples = self.samples_ns_per_op.clone();
        if samples.is_empty() {
            return;
        }
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let p50 = percentile_sorted(&samples, 0.50);
        let p95 = percentile_sorted(&samples, 0.95);
        let p99 = percentile_sorted(&samples, 0.99);
        let mean = samples.iter().sum::<f64>() / samples.len() as f64;
        let throughput_ops_s = if self.total_ns == 0 {
            0.0
        } else {
            self.total_iters as f64 / (self.total_ns as f64 / 1e9)
        };

        println!(
            "RESOLV_PARSERS_BENCH mode={} bench={} samples={} p50_ns_op={:.3} p95_ns_op={:.3} p99_ns_op={:.3} mean_ns_op={:.3} throughput_ops_s={:.3}",
            mode_label,
            bench_label,
            samples.len(),
            p50,
            p95,
            p99,
            mean,
            throughput_ops_s
        );
    }
}

fn percentile_sorted(sorted: &[f64], p: f64) -> f64 {
    debug_assert!((0.0..=1.0).contains(&p));
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn mode_label() -> &'static str {
    let label = std::env::var("FRANKENLIBC_RESOLV_BENCH_MODE")
        .ok()
        .or_else(|| std::env::var("FRANKENLIBC_MODE").ok());
    match label.as_deref() {
        Some("hardened") => "hardened",
        Some("strict") => "strict",
        _ => "raw",
    }
}

fn measure<F>(bench_label: &str, samples: usize, iters_per_sample: u64, mut op: F)
where
    F: FnMut(),
{
    let mut stats = BenchStats {
        samples_ns_per_op: Vec::with_capacity(samples),
        total_iters: 0,
        total_ns: 0,
    };

    for _ in 0..samples {
        let start = Instant::now();
        for _ in 0..iters_per_sample {
            op();
        }
        stats.record(
            iters_per_sample,
            start.elapsed().max(Duration::from_nanos(1)),
        );
    }

    stats.report(mode_label(), bench_label);
}

const HOSTS_LINE: &[u8] = b"127.0.0.1   localhost localhost.localdomain";
const SERVICES_LINE: &[u8] = b"http            80/tcp   www www-http   # World Wide Web HTTP";
const PROTOCOLS_LINE: &[u8] = b"tcp     6       TCP             # transmission control protocol";
const NETWORKS_LINE: &[u8] = b"link-local      169.254.0.0     localnet";
const ALIASES_LINE: &[u8] = b"postmaster: root, admin, oncall@example.com";
const GROUP_LINE: &[u8] = b"adm:x:4:syslog,ubuntu,operator";
const PASSWD_LINE: &[u8] = b"ubuntu:x:1000:1000:Ubuntu,,,:/home/ubuntu:/bin/bash";
const SHADOW_LINE: &[u8] = b"ubuntu:$y$j9T$rounds=100000$salt$hash:19800:0:99999:7:::";
const GSHADOW_LINE: &[u8] = b"sudo:!:root,admin:alice,bob";
const RPC_LINE: &[u8] = b"portmapper      100000  portmap sunrpc rpcbind";
const PROC_MAPS_LINE: &str =
    "7f1234500000-7f1234600000 r-xp 00010000 fd:01 12345 /usr/lib/libfoo.so";
const PROC_NET_ROUTE: &[u8] =
    b"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
lo\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n\
eth0\t00000000\t01010101\t0003\t0\t0\t0\t00000000\t0\t0\t0\n";
const PROC_NET_IF_INET6: &[u8] = b"00000000000000000000000000000001 01 80 10 80       lo\n\
fe800000000000000000000000000001 02 40 20 80   eth0\n";
const RESOLV_CONF_OPTIONS: &[u8] =
    b"options ndots:4 timeout:2 attempts:3 rotate use-vc\nnameserver 1.1.1.1\n";
const RESOLVER_QUERY_NAME: &str = "api.service.prod.cluster.example.com";
const NETGROUP_CONTENT: &[u8] = b"# /etc/netgroup snippet\n\
admins (host1,alice,example.com) (host2,bob,example.com)\n\
ops (host3,charlie,example.com)\n\
test-team (host4,,example.com) (host5,eve,)\n\
finance (host6,frank,example.com)\n\
admins (host7,grace,example.com)\n";

fn bench_parse_hosts_line() {
    measure(
        "parse_hosts_line_typical",
        SAMPLES,
        ITERS_PER_SAMPLE,
        || {
            let r = resolv::parse_hosts_line(black_box(HOSTS_LINE));
            black_box(r);
        },
    );
}

fn bench_parse_services_line() {
    measure(
        "parse_services_line_typical",
        SAMPLES,
        ITERS_PER_SAMPLE,
        || {
            let r = resolv::parse_services_line(black_box(SERVICES_LINE));
            black_box(r);
        },
    );
}

fn bench_parse_protocols_line() {
    measure(
        "parse_protocols_line_typical",
        SAMPLES,
        ITERS_PER_SAMPLE,
        || {
            let r = resolv::parse_protocols_line(black_box(PROTOCOLS_LINE));
            black_box(r);
        },
    );
}

fn bench_parse_networks_line() {
    measure(
        "parse_networks_line_typical",
        SAMPLES,
        ITERS_PER_SAMPLE,
        || {
            let r = resolv::parse_networks_line(black_box(NETWORKS_LINE));
            black_box(r);
        },
    );
}

fn bench_parse_aliases_line() {
    measure(
        "parse_aliases_line_typical",
        SAMPLES,
        ITERS_PER_SAMPLE,
        || {
            let r = aliases::parse_aliases_line(black_box(ALIASES_LINE));
            black_box(r);
        },
    );
}

fn bench_parse_group_line() {
    measure(
        "parse_group_line_typical",
        SAMPLES,
        ITERS_PER_SAMPLE,
        || {
            let r = grp::parse_group_line(black_box(GROUP_LINE));
            black_box(r);
        },
    );
}

fn bench_parse_passwd_line() {
    measure(
        "parse_passwd_line_typical",
        SAMPLES,
        ITERS_PER_SAMPLE,
        || {
            let r = pwd::parse_passwd_line(black_box(PASSWD_LINE));
            black_box(r);
        },
    );
}

fn bench_parse_shadow_line() {
    measure(
        "parse_shadow_line_typical",
        SAMPLES,
        ITERS_PER_SAMPLE,
        || {
            let r = pwd::shadow::parse_shadow_line(black_box(SHADOW_LINE));
            black_box(r);
        },
    );
}

#[inline(never)]
fn parse_gshadow_line_old(line: &[u8]) -> Option<pwd::gshadow::Gshadow> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.is_empty() || line.starts_with(b"#") {
        return None;
    }

    let fields: Vec<&[u8]> = line.split(|&b| b == b':').collect();
    if fields[0].is_empty() {
        return None;
    }

    let sg_passwd = fields.get(1).copied().unwrap_or(b"").to_vec();
    let sg_adm = fields.get(2).copied().unwrap_or(b"").to_vec();
    let sg_mem = if fields.len() > 3 {
        fields[3..].join(b":".as_slice())
    } else {
        Vec::new()
    };

    Some(pwd::gshadow::Gshadow {
        sg_namp: fields[0].to_vec(),
        sg_passwd,
        sg_adm,
        sg_mem,
    })
}

#[inline(never)]
fn parse_gshadow_line_current(line: &[u8]) -> Option<pwd::gshadow::Gshadow> {
    pwd::gshadow::parse_gshadow_line(line)
}

fn time_gshadow_parser(parser: fn(&[u8]) -> Option<pwd::gshadow::Gshadow>, iters: u64) -> f64 {
    let start = Instant::now();
    for _ in 0..iters {
        black_box(parser(black_box(GSHADOW_LINE)));
    }
    start.elapsed().as_nanos() as f64 / iters as f64
}

fn median(mut samples: Vec<f64>) -> f64 {
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

fn bench_parse_gshadow_line_ab() {
    let parity_cases: &[&[u8]] = &[
        b"sudo:!:root,admin:alice,bob",
        b"root:*::",
        b"wheel",
        b"wheel:::",
        b"wheel:!:root::alice:bob",
        b"g:x:a:b:c\r\n",
        b":*::",
        b"# comment",
        b"",
    ];
    for &line in parity_cases {
        assert_eq!(
            parse_gshadow_line_current(line),
            parse_gshadow_line_old(line),
            "gshadow parser mismatch for {line:?}"
        );
    }

    const AB_SAMPLES: usize = 60;
    const AB_ITERS: u64 = 10_000;
    let mut old = Vec::with_capacity(AB_SAMPLES);
    let mut new = Vec::with_capacity(AB_SAMPLES);
    let mut null_a = Vec::with_capacity(AB_SAMPLES);
    let mut null_b = Vec::with_capacity(AB_SAMPLES);

    for sample in 0..AB_SAMPLES {
        match sample % 3 {
            0 => {
                old.push(time_gshadow_parser(parse_gshadow_line_old, AB_ITERS));
                new.push(time_gshadow_parser(parse_gshadow_line_current, AB_ITERS));
                null_a.push(time_gshadow_parser(parse_gshadow_line_current, AB_ITERS));
                null_b.push(time_gshadow_parser(parse_gshadow_line_current, AB_ITERS));
            }
            1 => {
                new.push(time_gshadow_parser(parse_gshadow_line_current, AB_ITERS));
                null_b.push(time_gshadow_parser(parse_gshadow_line_current, AB_ITERS));
                old.push(time_gshadow_parser(parse_gshadow_line_old, AB_ITERS));
                null_a.push(time_gshadow_parser(parse_gshadow_line_current, AB_ITERS));
            }
            _ => {
                null_a.push(time_gshadow_parser(parse_gshadow_line_current, AB_ITERS));
                old.push(time_gshadow_parser(parse_gshadow_line_old, AB_ITERS));
                null_b.push(time_gshadow_parser(parse_gshadow_line_current, AB_ITERS));
                new.push(time_gshadow_parser(parse_gshadow_line_current, AB_ITERS));
            }
        }
    }

    let old = median(old);
    let new = median(new);
    let null_a = median(null_a);
    let null_b = median(null_b);
    println!("GSHADOW_PARSE_EQ cases={} status=PASS", parity_cases.len());
    println!(
        "GSHADOW_PARSE_AB old={old:.3}ns new={new:.3}ns new/old={:.4}",
        new / old
    );
    println!(
        "GSHADOW_PARSE_NULL a={null_a:.3}ns b={null_b:.3}ns b/a={:.4}",
        null_b / null_a
    );
}

fn bench_parse_rpc_line() {
    measure("parse_rpc_line_typical", SAMPLES, ITERS_PER_SAMPLE, || {
        let r = rpc::parse_rpc_line(black_box(RPC_LINE));
        black_box(r);
    });
}

fn bench_parse_maps_line() {
    measure("parse_maps_line_typical", SAMPLES, ITERS_PER_SAMPLE, || {
        let r = proc_maps::parse_maps_line(black_box(PROC_MAPS_LINE));
        black_box(r);
    });
}

fn bench_parse_proc_net_route_has_ipv4() {
    measure(
        "parse_proc_net_route_has_ipv4_typical",
        SAMPLES,
        ITERS_PER_SAMPLE,
        || {
            let r = resolv::parse_proc_net_route_has_ipv4(black_box(PROC_NET_ROUTE));
            black_box(r);
        },
    );
}

fn bench_parse_proc_net_if_inet6_has_ipv6() {
    measure(
        "parse_proc_net_if_inet6_has_ipv6_typical",
        SAMPLES,
        ITERS_PER_SAMPLE,
        || {
            let r = resolv::parse_proc_net_if_inet6_has_ipv6(black_box(PROC_NET_IF_INET6));
            black_box(r);
        },
    );
}

fn bench_parse_resolv_conf_options() {
    measure(
        "parse_resolv_conf_options_typical",
        SAMPLES,
        ITERS_PER_SAMPLE,
        || {
            let r = resolv::ResolverConfig::parse(black_box(RESOLV_CONF_OPTIONS));
            black_box(r);
        },
    );
}

fn bench_resolver_should_try_absolute_first() {
    let config = resolv::ResolverConfig::parse(b"options ndots:2\n");
    measure(
        "resolver_should_try_absolute_first_typical",
        SAMPLES,
        ITERS_PER_SAMPLE,
        || {
            let r = config.should_try_absolute_first(black_box(RESOLVER_QUERY_NAME));
            black_box(r);
        },
    );
}

fn bench_parse_netgroup_triples() {
    measure(
        "parse_netgroup_triples_match",
        SAMPLES,
        ITERS_PER_SAMPLE,
        || {
            let r =
                netgroup::parse_netgroup_triples(black_box(NETGROUP_CONTENT), black_box(b"admins"));
            black_box(r);
        },
    );
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("gshadow-ab") {
        bench_parse_gshadow_line_ab();
        return;
    }

    bench_parse_hosts_line();
    bench_parse_services_line();
    bench_parse_protocols_line();
    bench_parse_networks_line();
    bench_parse_aliases_line();
    bench_parse_group_line();
    bench_parse_passwd_line();
    bench_parse_shadow_line();
    bench_parse_rpc_line();
    bench_parse_maps_line();
    bench_parse_proc_net_route_has_ipv4();
    bench_parse_proc_net_if_inet6_has_ipv6();
    bench_parse_resolv_conf_options();
    bench_resolver_should_try_absolute_first();
    bench_parse_netgroup_triples();
}
