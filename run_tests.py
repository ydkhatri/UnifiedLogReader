#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Script to run the tests."""

import sys
import unittest

if __name__ == '__main__':
    print('Using Python version {0!s}'.format(sys.version))

    test_suite = unittest.TestLoader().discover('tests', pattern='*.py')
    test_results = unittest.TextTestRunner(verbosity=2).run(test_suite)
    if not test_results.wasSuccessful():
        sys.exit(1)
