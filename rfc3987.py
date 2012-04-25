#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2011 Daniel Gerber.
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.

r"""
Parsing and validation of URIs (RFC 3896) and IRIs (RFC 3987).

This module provides regular expressions according to `RFC 3986 "Uniform 
Resource Identifier (URI): Generic Syntax"
<http://tools.ietf.org/html/rfc3986>`_ and `RFC 3987 "Internationalized
Resource Identifiers (IRIs)" <http://tools.ietf.org/html/rfc3987>`_, and
utilities for composition and relative resolution of references.


API
---

`patterns`
    A dict of regular expressions (patterns) keyed by `rule names for URIs`_
    and `rule names for IRIs`_.
    
    Patterns are `str` instances (be it in python 2.x or 3.x) containing ASCII
    characters only. They can be compiled with regex_, without need for 
    any particular compilation flag::
    
        >>> import regex
        >>> uri = regex.compile('^%s$' % patterns['URI'])
        >>> m = uri.match('http://tools.ietf.org/html/rfc3986#appendix-A')
        >>> d = m.groupdict()
        >>> assert all([ d['scheme'] == 'http',
        ...              d['authority'] == 'tools.ietf.org',
        ...              d['path'] == '/html/rfc3986',
        ...              d['query'] == None,
        ...              d['fragment'] == 'appendix-A' ])
        >>> from unicodedata import lookup
        >>> smp = 'urn:' + lookup('OLD ITALIC LETTER A')  # U+00010300
        >>> assert not uri.match(smp)
        >>> assert regex.match('^%s$' % patterns['IRI'], smp)
        >>> assert not regex.match('^%s$' % patterns['relative_ref'], '#f#g')

        
    Alternatively, the standard library re_ module can be used *provided that*:

      - ``\u`` and ``\U`` escapes are preprocessed (see `issue3665
        <http://bugs.python.org/issue3665>`_)::
        
          >>> import re, sys, ast
          >>> re.compile(patterns['ucschar']) #doctest:+IGNORE_EXCEPTION_DETAIL
          Traceback (most recent call last):
            ...
            File "/usr/lib/python2.6/re.py", line 245, in _compile
              raise error, v # invalid expression
          error: bad character range
          >>> tpl = 'u"%s"' if sys.version_info[0] < 3 else '"%s"'
          >>> utext_pattern = ast.literal_eval(tpl % patterns['ucschar'])
          >>> assert re.compile(utext_pattern)

      - named capture groups do not occur on multiple branches of an
        alternation::

          >>> re.compile(patterns['path']) #doctest:+IGNORE_EXCEPTION_DETAIL
          Traceback (most recent call last):
            ...
            File "/usr/lib/python2.6/re.py", line 245, in _compile
              raise error, v # invalid expression
          error: redefinition of group name 'path' as group 2; was group 1
          >>> pat = format_patterns(path='outermost_group_name')['path']
          >>> assert re.compile(pat)

        
`format_patterns`
    {format_patterns.__doc__}
        
`compose`
    {compose.__doc__}

`resolve`
    {resolve.__doc__}


What's new
----------

version 1.3.0:

- python 3.x compatibility
- format_patterns 

version 1.2.1:

- compose, resolve

      
.. _re: http://docs.python.org/library/re
.. _regex: http://pypi.python.org/pypi/regex
.. _rule names for URIs: http://tools.ietf.org/html/rfc3986#appendix-A
.. _rule names for IRIs: http://tools.ietf.org/html/rfc3987#section-2.2

"""
__version__ = '1.3.0'

try:
    basestring
except NameError:
    basestring = str

try:
    import regex
except ImportError:
    from warnings import warn
    warn('Could not import regex.')
    del warn

__all__ = ('patterns', 'compose', 'resolve')


_common_rules = (

    ########   SCHEME   ########
    ('scheme',       r"[a-zA-Z][a-zA-Z0-9+.-]*"),

    ########   PORT   ########
    ('port',         r"[0-9]*"),

    ########   IP ADDRESSES   ########
    ('IP_literal',   r"\[(?:{IPv6address}|{IPvFuture})\]"),
    ('IPv6address', (r"(?:                             (?:{h16}:){{6}} {ls32}"
                     r"|                            :: (?:{h16}:){{5}} {ls32}"
                     r"|                    {h16}?  :: (?:{h16}:){{4}} {ls32}"
                     r"| (?:(?:{h16}:)?     {h16})? :: (?:{h16}:){{3}} {ls32}"
                     r"| (?:(?:{h16}:){{,2}}{h16})? :: (?:{h16}:){{2}} {ls32}"
                     r"| (?:(?:{h16}:){{,3}}{h16})? :: (?:{h16}:)      {ls32}"
                     r"| (?:(?:{h16}:){{,4}}{h16})? ::                 {ls32}"
                     r"| (?:(?:{h16}:){{,5}}{h16})? ::                 {h16} "
                     r"| (?:(?:{h16}:){{,6}}{h16})? ::                      )"
                      ).replace(' ', '')),
    ('ls32',         r"(?:{h16}:{h16}|{IPv4address})"),
    ('h16',          r"[0-9A-F]{{1,4}}"),
    ('IPv4address',  r"(?:{dec_octet}\.){{3}}{dec_octet}"),
    ('dec_octet',    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"),
    ('IPvFuture',    r"v[0-9A-F]+\.(?:{unreserved}|{sub_delims}|:)+"),

    ########  CHARACTER CLASSES   ########
    ('unreserved',    r"[a-zA-Z0-9_.~-]"),
    ('reserved',      r"(?:{gen_delims}|{sub_delims})"),
    ('pct_encoded',   r"%[0-9A-F][0-9A-F]"),
    ('gen_delims',    r"[:/?#[\]@]"),
    ('sub_delims',    r"[!$&'()*+,;=]"),

)


_uri_rules = (

    ########   REFERENCES   ########
    ('URI_reference',   r"(?:{URI}|{relative_ref})"),
    
    ('URI',             r"{absolute_URI}(?:\#{fragment})?"),
    ('absolute_URI',    r"{scheme}:{hier_part}(?:\?{query})?"),
    ('hier_part',      (r"(?://{authority}{path_abempty}"
                        r"|{path_absolute}|{path_rootless}|{path_empty})")),
    
    ('relative_ref',    r"{relative_part}(?:\?{query})?(?:\#{fragment})?"),
    ('relative_part',  (r"(?://{authority}{path_abempty}"
                        r"|{path_absolute}|{path_noscheme}|{path_empty})")),

    ########   AUTHORITY   ########
    ('authority', r"(?:{userinfo}@)?{host}(?::{port})?"),
    ('host',      r"(?:{IP_literal}|{IPv4address}|{reg_name})"),
    ('userinfo',  r"(?:{unreserved}|{pct_encoded}|{sub_delims}|:)*"),
    ('reg_name',  r"(?:{unreserved}|{pct_encoded}|{sub_delims})*"),

    ########   PATH   ########
    ('path',         (r"(?:{path_abempty}|{path_absolute}|{path_noscheme}"
                      r"|{path_rootless}|{path_empty})")),
    ('path_abempty',  r"(?:/{segment})*"),
    ('path_absolute', r"/(?:{segment_nz}(?:/{segment})*)?"),
    ('path_noscheme', r"{segment_nz_nc}(?:/{segment})*"),
    ('path_rootless', r"{segment_nz}(?:/{segment})*"),
    ('path_empty',    r""),

    ('segment',       r"{pchar}*"),
    ('segment_nz',    r"{pchar}+"),
    ('segment_nz_nc', r"(?:{unreserved}|{pct_encoded}|{sub_delims}|@)+"),

    ########   QUERY   ########
    ('query',         r"(?:{pchar}|/|\?)*"),

    ########   FRAGMENT   ########
    ('fragment',      r"(?:{pchar}|/|\?)*"),

    ########  CHARACTER CLASSES   ########
    ('pchar',         r"(?:{unreserved}|{pct_encoded}|{sub_delims}|:|@)"),
    ('unreserved',    r"[a-zA-Z0-9._~-]"),

)


#: http://tools.ietf.org/html/rfc3987
#: January 2005
_iri_rules = (

    ########   REFERENCES   ########
    ('IRI_reference',   r"(?:{IRI}|{irelative_ref})"),
    ('IRI',             r"{absolute_IRI}(?:\#{ifragment})?"),
    ('absolute_IRI',    r"{scheme}:{ihier_part}(?:\?{iquery})?"),
    ('irelative_ref',  (r"(?:{irelative_part}"
                        r"(?:\?{iquery})?(?:\#{ifragment})?)")),

    ('ihier_part',     (r"(?://{iauthority}{ipath_abempty}"
                        r"|{ipath_absolute}|{ipath_rootless}|{ipath_empty})")),
    ('irelative_part', (r"(?://{iauthority}{ipath_abempty}"
                        r"|{ipath_absolute}|{ipath_noscheme}|{ipath_empty})")),


    ########   AUTHORITY   ########
    ('iauthority', r"(?:{iuserinfo}@)?{ihost}(?::{port})?"),
    ('iuserinfo',  r"(?:{iunreserved}|{pct_encoded}|{sub_delims}|:)*"),
    ('ihost',      r"(?:{IP_literal}|{IPv4address}|{ireg_name})"),

    ('ireg_name',  r"(?:{iunreserved}|{pct_encoded}|{sub_delims})*"),

    ########   PATH   ########
    ('ipath',         (r"(?:{ipath_abempty}|{ipath_absolute}|{ipath_noscheme}"
                       r"|{ipath_rootless}|{ipath_empty})")),

    ('ipath_empty',    r""),
    ('ipath_rootless', r"{isegment_nz}(?:/{isegment})*"),
    ('ipath_noscheme', r"{isegment_nz_nc}(?:/{isegment})*"),
    ('ipath_absolute', r"/(?:{isegment_nz}(?:/{isegment})*)?"),
    ('ipath_abempty',  r"(?:/{isegment})*"),

    ('isegment_nz_nc', r"(?:{iunreserved}|{pct_encoded}|{sub_delims}|@)+"),
    ('isegment_nz',    r"{ipchar}+"),
    ('isegment',       r"{ipchar}*"),

    ########   QUERY   ########
    ('iquery',    r"(?:{ipchar}|{iprivate}|/|\?)*"),

    ########   FRAGMENT   ########
    ('ifragment', r"(?:{ipchar}|/|\?)*"),

    ########   CHARACTER CLASSES   ########
    ('ipchar',      r"(?:{iunreserved}|{pct_encoded}|{sub_delims}|:|@)"),
    ('iunreserved', r"(?:[a-zA-Z0-9._~-]|{ucschar})"),
    ('iprivate', r"[\uE000-\uF8FF\U000F0000-\U000FFFFD\U00100000-\U0010FFFD]"),
    ('ucschar', (r"[\xA0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF"
                 r"\U00010000-\U0001FFFD\U00020000-\U0002FFFD"
                 r"\U00030000-\U0003FFFD\U00040000-\U0004FFFD"
                 r"\U00050000-\U0005FFFD\U00060000-\U0006FFFD"
                 r"\U00070000-\U0007FFFD\U00080000-\U0008FFFD"
                 r"\U00090000-\U0009FFFD\U000A0000-\U000AFFFD"
                 r"\U000B0000-\U000BFFFD\U000C0000-\U000CFFFD"
                 r"\U000D0000-\U000DFFFD\U000E1000-\U000EFFFD]")),

)


def format_patterns(**names):
    """Returns a dict of regular expressions keyed by rule name.

    By default, the formatted patterns contain no named capture groups.
    To wrap the pattern of a rule in a named group, pass a keyword 
    argument of the form rule_name='group_name'.
    For a useful set of group names, see also `patterns`.
    """
    formatted = {}
    for name, pat in _common_rules[::-1] + _uri_rules[::-1] + _iri_rules[::-1]:
        if name in names:
            pat = '(?P<%s>%s)' % (names[name], pat)
        formatted[name] = pat.format(**formatted)
    return formatted

DEFAULT_GROUP_NAMES = dict(
        (2*[n] for n in [
                'scheme', 'port',
                'IPv6address', 'IPv4address', 'IPvFuture',
                'URI_reference',
                'URI', 'absolute_URI', 'relative_ref', 'relative_part',
                'authority', 'host', 'userinfo', 'reg_name',
                'query', 'fragment',
                'IRI_reference',
                'IRI', 'absolute_IRI', 'irelative_ref', 'irelative_part',
                'iauthority', 'ihost', 'iuserinfo', 'ireg_name',
                'iquery', 'ifragment',
                ]),
        path_abempty='path', path_absolute='path', path_noscheme='path',
        path_rootless='path', path_empty='path',
        ipath_abempty='ipath', ipath_absolute='ipath', ipath_noscheme='ipath',
        ipath_rootless='ipath', ipath_empty='ipath')

#: mapping of rfc3986 / rfc3987 rule names to regular expressions
patterns = format_patterns(**DEFAULT_GROUP_NAMES)


def _get_compiled_pattern(rule='^%(IRI_reference)s$'):
    """Returns a compiled pattern object from a rule name or template."""
    c = _get_compiled_pattern._cache
    if rule not in c:
        obj = patterns.get(rule) or rule % patterns
        c[rule] = regex.compile(obj)
    return c[rule]
_get_compiled_pattern._cache = {}


def _i2u(dic):
    for (name, iname) in [('authority', 'iauthority'), ('path', 'ipath'),
                          ('query', 'iquery'), ('fragment', 'ifragment')]:
        if not dic.get(name):
            dic[name] = dic.get(iname)


def compose(scheme=None, authority=None, path='', query=None, fragment=None,
            iauthority=None, ipath='', iquery=None, ifragment=None, **kw):
    """Returns an URI composed_ from named parts.

    .. _composed: http://tools.ietf.org/html/rfc3986#section-5.3
    """
    _i2u(locals())
    res = ''
    if scheme is not None:
        res += scheme + ':'
    if authority is not None:
        res += '//' + authority
    res += path
    if query is not None:
        res += '?' + query
    if fragment is not None:
        res += '#' + fragment
    return res


def resolve(base, uriref, strict=True, return_parts=False):
    """Resolves_ an `URI reference` relative to a `base` URI.
    
    `Test cases <http://tools.ietf.org/html/rfc3986#section-5.4>`_::
    
        >>> base = "http://a/b/c/d;p?q"
        >>> for relative, resolved in {
        ...     "g:h"           :  "g:h",
        ...     "g"             :  "http://a/b/c/g",
        ...     "./g"           :  "http://a/b/c/g",
        ...     "g/"            :  "http://a/b/c/g/",
        ...     "/g"            :  "http://a/g",
        ...     "//g"           :  "http://g",
        ...     "?y"            :  "http://a/b/c/d;p?y",
        ...     "g?y"           :  "http://a/b/c/g?y",
        ...     "#s"            :  "http://a/b/c/d;p?q#s",
        ...     "g#s"           :  "http://a/b/c/g#s",
        ...     "g?y#s"         :  "http://a/b/c/g?y#s",
        ...     ";x"            :  "http://a/b/c/;x",
        ...     "g;x"           :  "http://a/b/c/g;x",
        ...     "g;x?y#s"       :  "http://a/b/c/g;x?y#s",
        ...     ""              :  "http://a/b/c/d;p?q",
        ...     "."             :  "http://a/b/c/",
        ...     "./"            :  "http://a/b/c/",
        ...     ".."            :  "http://a/b/",
        ...     "../"           :  "http://a/b/",
        ...     "../g"          :  "http://a/b/g",
        ...     "../.."         :  "http://a/",
        ...     "../../"        :  "http://a/",
        ...     "../../g"       :  "http://a/g",
        ...     "../../../g"    :  "http://a/g",
        ...     "../../../../g" :  "http://a/g",
        ...     "/./g"          :  "http://a/g",
        ...     "/../g"         :  "http://a/g",
        ...     "g."            :  "http://a/b/c/g.",
        ...     ".g"            :  "http://a/b/c/.g",
        ...     "g.."           :  "http://a/b/c/g..",
        ...     "..g"           :  "http://a/b/c/..g",
        ...     "./../g"        :  "http://a/b/g",
        ...     "./g/."         :  "http://a/b/c/g/",
        ...     "g/./h"         :  "http://a/b/c/g/h",
        ...     "g/../h"        :  "http://a/b/c/h",
        ...     "g;x=1/./y"     :  "http://a/b/c/g;x=1/y",
        ...     "g;x=1/../y"    :  "http://a/b/c/y",
        ...     }.items():
        ...     assert resolve(base, relative) == resolved

    
    If `return_parts` is True, returns a dict of named parts instead of
    a string.
        
    .. _Resolves: http://tools.ietf.org/html/rfc3986#section-5.2

    """
    #base = normalize(base)
    if isinstance(base, basestring):
        m = _get_compiled_pattern('^%(IRI)s$').match(base)
        if not m:
            raise ValueError('Invalid base IRI %r.' % base)
        B = m.groupdict()
    else:
        B = dict(base)
    _i2u(B)
    if not B.get('scheme'):
        raise ValueError('Expected an IRI (with scheme), not %r.' % base)
    
    if isinstance(uriref, basestring):
        m = _get_compiled_pattern('%(IRI_reference)s$').match(uriref)
        if not m:
            raise ValueError('Invalid IRI reference %r.' % uriref)
        R = m.groupdict()
    else:
        R = dict(uriref)
    _i2u(R)
    
    _last_segment = _get_compiled_pattern('(?<=^|/)%(segment)s$')
    _dot_segments = _get_compiled_pattern(r'^\.{1,2}(?:/|$)|(?<=/)\.(?:/|$)')
    _2dots_segments = _get_compiled_pattern(r'/?%(segment)s/\.{2}(?:/|$)')
    
    if R['scheme'] and (strict or R['scheme'] != B['scheme']):
        T = R
    else:
        T = {}
        T['scheme'] = B['scheme']
        if R['authority'] is not None:
            T['authority'] = R['authority']
            T['path'] = R['path']
            T['query'] = R['query']
        else:
            T['authority'] = B['authority']
            if R['path']:
                if R['path'][:1] == "/":
                    T['path'] = R['path']
                elif B['authority'] is not None and not B['path']:
                    T['path'] = '/%s' % R['path']
                else:
                    T['path'] = _last_segment.sub(R['path'], B['path'])
                T['query'] = R['query']
            else:
                T['path'] = B['path']
                if R['query'] is not None:
                    T['query'] = R['query']
                else:
                    T['query'] = B['query']
        T['fragment'] = R['fragment']
    T['path'] =  _dot_segments.sub('', T['path'])
    c = 1
    while c:
        T['path'], c =  _2dots_segments.subn('/', T['path'], 1)
    if return_parts:
        return T
    else:
        return compose(**T)


def normalize(uri):
    "Syntax-Based Normalization"
    # TODO:
    raise NotImplementedError


if __name__ == '__main__':
    import sys
    if not sys.argv[1:]:
        print('Valid arguments are "--all" or rule names from:')
        print('  '.join(sorted(patterns)))
    elif sys.argv[1] == '--all':
        for name in patterns:
            print(name + ':')
            print(patterns[name])
    else:
        for name in sys.argv[1:]:
            print(patterns[name])
