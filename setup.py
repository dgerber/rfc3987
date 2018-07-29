#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import rfc3987

desc, _sep, long_desc = rfc3987.__doc__.partition('.')

setup(name='rfc3987',
      version= rfc3987.__version__,
      description=desc.strip(),
      long_description=long_desc.lstrip().format(**rfc3987.__dict__),
      author='Daniel Gerber',
      author_email='daniel.g.gerber@gmail.com',
      url='http://pypi.python.org/pypi/rfc3987',
      download_url='https://github.com/dgerber/rfc3987',
      py_modules=['rfc3987'],
      # requires=['regex'],
      keywords='URI IRI URL rfc3986 rfc3987 validation',
      license='GNU GPLv3+',
      classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet'
        ]
     )
