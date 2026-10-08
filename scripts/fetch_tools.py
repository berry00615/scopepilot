"""Explicit developer download: official, pinned archives only. Never executed by the app."""
import hashlib
import json
import shutil
import urllib.request
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
lock = json.loads((root / 'tool-lock.json').read_text())
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
downloads = root / '.downloads'
downloads.mkdir(exist_ok=True)
records = []
if shutil.disk_usage(root).free < 2 * 1024**3:
    raise SystemExit('Less than 2 GiB free: download refused')
for name, spec in lock.items():
    archive = downloads / spec['archive']
    if not archive.exists():
        with opener.open(spec['url'], timeout=60) as response, archive.open('wb') as output:
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > spec['archive_bytes']:
                    raise RuntimeError('Download exceeds pinned size')
                output.write(chunk)
    if archive.stat().st_size != spec['archive_bytes']:
        raise RuntimeError(f'Archive size mismatch: {name}')
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != spec['sha256']:
        raise RuntimeError(f'Official release digest mismatch: {name}')
    with opener.open(spec['checksums_url'], timeout=30) as response:
        checksums = response.read(65536).decode('utf-8')
    if not any(line.split() == [digest, spec['archive']] for line in checksums.splitlines()):
        raise RuntimeError(f'Official checksums file mismatch: {name}')
    destination = root / '.tools' / name
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as package:
        member = package.getinfo(spec['executable'])
        if member.file_size > 300 * 1024**2:
            raise RuntimeError('Executable exceeds size budget')
        executable = destination / spec['executable']
        executable.write_bytes(package.read(member))
        for item in package.infolist():
            if '/' not in item.filename and '\\' not in item.filename and item.filename.lower().startswith('license'):
                (destination / item.filename).write_bytes(package.read(item))
    records.append({**spec, 'verification': 'Archive matches GitHub release asset digest AND official release checksums file', 'executable_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(), 'installed_bytes': sum(p.stat().st_size for p in destination.iterdir() if p.is_file())})
(root / 'docs' / 'tool-installation.json').write_text(json.dumps(records, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print('Verified official archives and installed project-local binaries; no tool was executed.')
