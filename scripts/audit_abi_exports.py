import re, pathlib, sys

root = pathlib.Path('crates/frankenlibc-abi/src')
missing = []
total = 0
for path in sorted(root.rglob('*.rs')):
    lines = path.read_text().splitlines()
    for i, line in enumerate(lines):
        m = re.match(r'\s*pub (?:unsafe )?extern "C" fn (\w+)', line)
        if not m:
            continue
        total += 1
        # Look back over the attribute/doc block for an export attribute.
        j = i - 1
        exported = False
        while j >= 0:
            prev = lines[j].strip()
            if prev.startswith('#['):
                if 'no_mangle' in prev:
                    exported = True
                    break
            elif prev.startswith('///') or prev.startswith('//') or prev == '':
                pass
            else:
                break
            j -= 1
        if not exported:
            missing.append((str(path), i + 1, m.group(1)))

print(f'pub extern "C" fn total={total} missing_export={len(missing)}')
for path, line, name in missing:
    print(f'  {path}:{line}  {name}')
