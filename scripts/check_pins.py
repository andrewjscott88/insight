"""Supply-chain pin check: container images by digest and GitHub Actions by full commit SHA.

Images: the Dockerfile's base images, and every third-party image a workflow starts with ``docker run``
(code review L7: they run with the repository mounted or on the host network). Images the workflows build
themselves (``insight:*``) and images named by a variable (``"${IMAGE}@${DIGEST}"``) are not third-party.

python scripts/check_pins.py            # report (GitHub warning annotations), exit 0
python scripts/check_pins.py --strict   # release gate: exit 1 if anything is pinned only by tag
"""

from __future__ import annotations

import argparse
import re
import shlex
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FROM = re.compile(r'^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)', re.IGNORECASE | re.MULTILINE)
USES = re.compile(r'^\s*-?\s*uses:\s*(?P<ref>\S+)', re.MULTILINE)
SHA = re.compile(r'@[0-9a-f]{40}$')
DIGEST = re.compile(r'@sha256:[0-9a-f]{64}$')
#: ``docker run`` options that take a value (the next word); any other option is a flag.
RUN_VALUE_OPTIONS = frozenset({
    '-v', '--volume', '-p', '--publish', '-e', '--env', '--env-file', '--name', '--network', '--tmpfs',
    '--cap-drop', '--cap-add', '--security-opt', '--entrypoint', '-w', '--workdir', '-u', '--user', '--mount',
    '--platform', '--add-host', '-l', '--label', '-h', '--hostname', '--memory', '--cpus', '--pull',
})  # fmt: skip
#: Images the workflows build themselves.
LOCAL_IMAGES = ('insight:',)


def unpinned_images(dockerfile: Path) -> list[str]:
    stages = {m.group(1).lower() for m in re.finditer(r'\bAS\s+(\S+)', dockerfile.read_text(), re.IGNORECASE)}
    found = []
    for match in FROM.finditer(dockerfile.read_text()):
        image = match.group('image')
        if image.lower() in stages or image.startswith('$'):
            continue
        if '@sha256:' not in image:
            found.append(f'{dockerfile.name}: base image {image} is not pinned by digest')
    return found


def unpinned_actions(workflow: Path) -> list[str]:
    found = []
    for match in USES.finditer(workflow.read_text()):
        ref = match.group('ref').strip('\'"')
        if ref.startswith(('./', 'docker://')):
            continue
        if not SHA.search(ref):
            found.append(f'{workflow.name}: {ref} is not pinned to a commit SHA')
    return found


def _commands(text: str) -> list[str]:
    """Every ``docker run`` command, with backslash continuations and YAML-folded lines joined."""
    lines = text.splitlines()
    commands = []
    for index, line in enumerate(lines):
        if 'docker run' not in line:
            continue
        command = line[line.index('docker run') :]
        indent = len(line) - len(line.lstrip())
        following = index + 1
        while following < len(lines):
            nxt = lines[following]
            continued = command.rstrip().endswith('\\')
            folded = (
                nxt.strip() and len(nxt) - len(nxt.lstrip()) == indent and not nxt.lstrip().startswith('-')
            )
            if not (continued or (folded and '>-' in lines[index - 1])):
                break
            command = command.rstrip().removesuffix('\\') + ' ' + nxt.strip()
            following += 1
        commands.append(command)
    return commands


def run_images(text: str) -> list[str]:
    """The image of each ``docker run`` command in a workflow's text."""
    images = []
    for command in _commands(text):
        words = shlex.split(command.replace('${', '__').replace('}', '__'), comments=True)[2:]
        index = 0
        while index < len(words) and words[index].startswith('-'):
            word = words[index]
            index += 2 if word in RUN_VALUE_OPTIONS else 1
        if index < len(words):
            images.append(words[index])
    return images


def unpinned_run_images(workflow: Path) -> list[str]:
    found = []
    for image in run_images(workflow.read_text()):
        if image.startswith(('__', '"__')) or image.startswith(LOCAL_IMAGES):
            continue
        if not DIGEST.search(image):
            found.append(f'{workflow.name}: docker run image {image} is not pinned by digest')
    return found


def problems(root: Path = ROOT) -> list[str]:
    found = unpinned_images(root / 'Dockerfile')
    for workflow in sorted((root / '.github' / 'workflows').glob('*.y*ml')):
        found += unpinned_actions(workflow)
        found += unpinned_run_images(workflow)
    return found


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--strict', action='store_true')
    args = parser.parse_args(argv)
    found = problems()
    level = 'error' if args.strict else 'warning'
    for problem in found:
        print(f'::{level}::{problem}')
    if not found:
        print('All base images and actions are pinned.')
    return 1 if found and args.strict else 0


if __name__ == '__main__':
    sys.exit(main())
