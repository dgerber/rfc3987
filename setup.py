#!/usr/bin/env python

from distutils.core import setup
import rfc3987

desc, _sep, long_desc = rfc3987.__doc__.partition('.')

setup(name='rfc3987',
      version= rfc3987.__version__,
      description=desc,
      long_description=long_desc.lstrip().format(**rfc3987.__dict__),
      author='Daniel Gerber',
      author_email='daniel.g.gerber@gmail.com',
      url='http://pypi.python.org/pypi/rfc3987',
      download_url='https://github.com/dgerber/rfc3987',
      py_modules=['rfc3987'],
      requires=['regex'],
      keywords='URI IRI URL rfc3986 rfc3987 validation',
      classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet'
        ]
     )
