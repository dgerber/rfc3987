#!/usr/bin/env python

from distutils.core import setup
from rfc3987 import __version__

setup(name='rfc3987',
      version= __version__,
      description='Parsing and validation of URIs and IRIs',
      long_description='This module provides regular expressions according to RFC 3986 "Uniform Resource Identifier (URI): Generic Syntax" and RFC 3987 "Internationalized Resource Identifiers (IRIs)"',
      author='Daniel Gerber',
      url='https://gist.github.com/1333605',
      py_modules=['rfc3987'],
      requires=['regex'],
      classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet'
        ]
     )
