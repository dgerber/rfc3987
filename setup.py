#!/usr/bin/env python

from distutils.core import setup
from rfc3987 import __version__

with open('README.rst') as f:
    long_description = f.read()

setup(name='rfc3987',
      version= __version__,
      description='Parsing and validation of URIs and IRIs',
      long_description=long_description,
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
