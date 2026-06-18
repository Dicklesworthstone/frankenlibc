//! Stdio parser, formatter, and buffering benchmarks.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use frankenlibc_core::stdio::{
    BufMode, FormatFlags, FormatSpec, LengthMod, OpenFlags, Precision, StdioStream, Width,
    format_signed, format_str, format_unsigned, parse_format_string, snprintb::format_snprintb,
};

fn write_only_flags() -> OpenFlags {
    OpenFlags {
        readable: false,
        writable: true,
        append: false,
        truncate: true,
        create: true,
        binary: false,
        exclusive: false,
        cloexec: false,
    }
}

fn bench_printf_parse(c: &mut Criterion) {
    let formats: &[(&str, &[u8])] = &[
        ("literal", b"frankenlibc stdio hot path"),
        ("mixed", b"fd=%d path=%-24s errno=%#x\n"),
        ("positional", b"%2$*1$d:%3$.8s:%4$p"),
    ];
    let mut group = c.benchmark_group("stdio_printf_parse");

    for &(name, fmt) in formats {
        group.throughput(Throughput::Bytes(fmt.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), fmt, |b, input| {
            b.iter(|| black_box(parse_format_string(black_box(input))));
        });
    }
    group.finish();
}

fn bench_printf_render(c: &mut Criterion) {
    let signed_spec = FormatSpec::new(
        FormatFlags {
            force_sign: true,
            zero_pad: true,
            ..FormatFlags::default()
        },
        Width::Fixed(16),
        Precision::None,
        LengthMod::Ll,
        b'd',
        None,
    );
    let string_spec = FormatSpec::new(
        FormatFlags {
            left_justify: true,
            ..FormatFlags::default()
        },
        Width::Fixed(32),
        Precision::Fixed(18),
        LengthMod::None,
        b's',
        None,
    );

    let mut group = c.benchmark_group("stdio_printf_render");
    group.throughput(Throughput::Elements(1));

    group.bench_function("signed_decimal", |b| {
        b.iter(|| {
            let mut out = Vec::with_capacity(32);
            format_signed(black_box(-1_234_567_890_123), &signed_spec, &mut out);
            black_box(out);
        });
    });

    group.bench_function("bounded_string", |b| {
        b.iter(|| {
            let mut out = Vec::with_capacity(40);
            format_str(
                black_box(b"frankenlibc-buffered-stdio"),
                &string_spec,
                &mut out,
            );
            black_box(out);
        });
    });
    group.finish();
}

// Isolates the decimal digit-generation core (render_digits) by formatting
// with a plain `%llu` spec (no width/precision/flags), so padding and flag
// handling do not dilute the measurement. Sweeps a realistic spread of
// magnitudes plus the 20-digit worst case (u64::MAX).
fn bench_int_digit_generation(c: &mut Criterion) {
    let plain_unsigned = FormatSpec::new(
        FormatFlags::default(),
        Width::None,
        Precision::None,
        LengthMod::Ll,
        b'u',
        None,
    );
    // A fixed corpus spanning 1..20 decimal digits.
    let values: [u64; 12] = [
        0,
        7,
        42,
        999,
        12_345,
        678_901,
        45_678_912,
        3_456_789_012,
        987_654_321_098,
        76_543_210_987_654,
        9_007_199_254_740_993,
        u64::MAX,
    ];

    let mut group = c.benchmark_group("stdio_printf_render");
    group.throughput(Throughput::Elements(values.len() as u64));
    group.bench_function("unsigned_decimal_sweep", |b| {
        b.iter(|| {
            let mut out = Vec::with_capacity(24);
            for &v in &values {
                out.clear();
                format_unsigned(black_box(v), &plain_unsigned, &mut out);
                black_box(&out);
            }
        });
    });
    group.finish();
}

fn bench_snprintb_named_bits(c: &mut Criterion) {
    const FLAGS_FMT: &[u8] = b"\x10\x01UP\x02BROADCAST\x03DEBUG\x04LOOPBACK\x05POINTOPOINT\x06RUNNING\x07NOARP\x08PROMISC\x09NOTRAILERS\x0aALLMULTI\x0bMASTER\x0cMULTICAST";
    const VALUES: [u64; 8] = [
        0,
        0b1,
        0b11,
        0b101101,
        0b11111111,
        0b100100100100,
        0b111111111111,
        u64::MAX,
    ];

    let mut group = c.benchmark_group("stdio_snprintb");
    group.throughput(Throughput::Elements(VALUES.len() as u64));
    group.bench_function("named_bits_stream_12", |b| {
        b.iter(|| {
            let mut total_len = 0usize;
            for &value in &VALUES {
                let out = format_snprintb(black_box(FLAGS_FMT), black_box(value));
                total_len += out.len();
                black_box(out);
            }
            black_box(total_len);
        });
    });
    group.finish();
}

fn bench_stream_buffering(c: &mut Criterion) {
    let payload = [b'x'; 256];
    let mut group = c.benchmark_group("stdio_stream_buffer");
    group.throughput(Throughput::Bytes(payload.len() as u64));

    group.bench_function("full_buffered_write", |b| {
        b.iter(|| {
            let mut stream = StdioStream::with_mode(-1, write_only_flags(), BufMode::Full);
            assert!(stream.set_buffering(BufMode::Full, 4096));
            for _ in 0..16 {
                let result = stream.buffer_write(black_box(&payload)).expect("writable");
                black_box(result.buffered);
                black_box(result.flush_data.len());
                if result.flush_needed {
                    stream.mark_flushed();
                }
            }
            black_box(stream.pending_flush().len());
        });
    });

    group.bench_function("line_buffered_write", |b| {
        b.iter(|| {
            let mut stream = StdioStream::with_mode(-1, write_only_flags(), BufMode::Line);
            assert!(stream.set_buffering(BufMode::Line, 4096));
            for _ in 0..16 {
                let result = stream
                    .buffer_write(black_box(b"metric=value status=ok\n"))
                    .expect("writable");
                black_box(result.flushed_from_buffer);
                black_box(result.flush_data.len());
                if result.flush_needed {
                    stream.mark_flushed();
                }
            }
            black_box(stream.pending_flush().len());
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_printf_parse,
    bench_printf_render,
    bench_int_digit_generation,
    bench_snprintb_named_bits,
    bench_stream_buffering
);
criterion_main!(benches);
