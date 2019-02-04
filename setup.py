#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Installation and deployment script."""

import glob
import os
import sys

try:
  from setuptools import find_packages, setup
except ImportError:
  from distutils.core import find_packages, setup

# Change PYTHONPATH to include UnifiedLog so that we can get the version.
sys.path.insert(0, '.')

import UnifiedLog  # pylint: disable=wrong-import-position


unifiedlog_description = (
    'A parser for Unified logging .tracev3 files.')

unifiedlog_long_description = (
    'A parser for Unified logging .tracev3 files.')

setup(
    name='UnifiedLog',
    version=UnifiedLog.__version__,
    description=unifiedlog_description,
    long_description=unifiedlog_long_description,
    license='MIT',
    url='https://github.com/ydkhatri/UnifiedLogReader',
    maintainer='Yogesh Khatri',
    maintainer_email='yogesh@swiftforensics.com',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Console',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ],
    packages=find_packages('.', exclude=[
        'tests', 'tests.*']),
    package_dir={
        'UnifiedLog': 'UnifiedLog'
    },
    scripts=glob.glob(os.path.join('scripts', '[A-Za-z]*.py')),
    data_files=[
        ('share/doc/UnifiedLog', [
            'LICENSE.txt', 'README.md']),
    ],
)
