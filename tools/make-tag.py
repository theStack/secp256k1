#!/usr/bin/env python3
'''
Make a new release tag, performing a few checks.

Usage: make-tag.py <tag>
'''
import os
import subprocess
import re
import sys
import collections

import treehash512

GIT = os.getenv("GIT", "git")

# Full version specification
VersionSpec = collections.namedtuple('VersionSpec', ['major', 'minor', 'patch'])

def version_name(spec):
    '''
    Short version name for comparison.
    '''
    return f"{spec.major}.{spec.minor}.{spec.patch}"

def parse_tag(tag):
    '''
    Parse a version tag. Valid version tags are

    - v1.2.3
    '''
    m = re.match(r"^v([0-9]+)\.([0-9]+)\.([0-9]+)$", tag)

    if m is None:
        print(f"Invalid tag {tag}", file=sys.stderr)
        sys.exit(1)

    major = m.group(1)
    minor = m.group(2)
    patch = m.group(3)

    return VersionSpec(int(major), int(minor), int(patch))

def check_buildsystem(spec):
    '''
    Parse configure.ac and return
    (major, minor, patch)
    '''
    info = {}
    filename = 'configure.ac'
    pattern = r"define\(_PKG_VERSION_([A-Z_]+), ([0-9a-z]+)\)"

    with open(filename) as f:
        for line in f:
            m = re.match(pattern, line)
            if m:
                info[m.group(1)] = m.group(2)
    # check if IS_RELEASE is set
    if info["IS_RELEASE"] != "true":
        print(f'{filename}: IS_RELEASE is not set to true', file=sys.stderr)
        sys.exit(1)

    cfg_spec = VersionSpec(
            int(info['MAJOR']),
            int(info['MINOR']),
            int(info['PATCH']),
        )

    if cfg_spec != spec:
        print(f"{filename}: Version from tag {version_name(spec)} doesn't match specified version {version_name(cfg_spec)}", file=sys.stderr)
        sys.exit(1)

def main():
    try:
        tag = sys.argv[1]
    except IndexError:
        print("Usage: make-tag.py <tag>, e.g. v0.7.2", file=sys.stderr)
        sys.exit(1)

    spec = parse_tag(tag)

    # Check that the script is called from repo root
    if not os.path.exists('.git'):
        print('Execute this script at the root of the repository', file=sys.stderr)
        sys.exit(1)

    # Check if working directory clean
    if subprocess.call([GIT, 'diff-index', '--quiet', 'HEAD']):
        print('Git working directory is not clean. Commit changes first.', file=sys.stderr)
        sys.exit(1)

    # Check version components against configure.ac in git tree
    check_buildsystem(spec)

    # Generate base message
    msg = 'libsecp256k1 ' + version_name(spec) + '\n'

    # Add treehash header
    msg += "\n"
    msg += 'Tree-SHA512: ' + treehash512.tree_sha512sum() + '\n'

    # Finally, make the tag
    print(msg)
    return subprocess.call([GIT, "tag", "-s", tag, "-m", msg])

if __name__ == '__main__':
    sys.exit(main())
