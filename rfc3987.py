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

"""
Parsing and validation of URIs (RFC 3896) and IRIs (RFC 3987).

This module provides regular expressions according to `RFC 3986`_ "Uniform 
Resource Identifier (URI): Generic Syntax" and `RFC 3987`_ "Internationalized 
Resource Identifiers (IRIs)", and utilities for composition and relative
resolution:

*patterns*
    A mapping of regular expressions keyed by `rule names for URIs`_ and 
    `for IRIs`_. ::

        >>> u = regex.compile('^%s$' % patterns['URI'])
        >>> m = u.match(u'http://tools.ietf.org/html/rfc3986#appendix-A')
        >>> assert m.groupdict() == dict(scheme=u'http',
        ...                              authority=u'tools.ietf.org',
        ...                              userinfo=None, host=u'tools.ietf.org',
        ...                              port=None, path=u'/html/rfc3986',
        ...                              query=None, fragment=u'appendix-A')
        >>> assert not u.match(u'urn:\U00010300')
        >>> assert regex.match('^%s$' % patterns['IRI'], u'urn:\U00010300')
        >>> assert not regex.match('^%s$' % patterns['relative_ref'], '#f#g')

*compose*
    {compose.__doc__}

*resolve*
    {resolve.__doc__}


.. _RFC 3986: http://tools.ietf.org/html/rfc3986
.. _RFC 3987: http://tools.ietf.org/html/rfc3987
.. _rule names for URIs: http://tools.ietf.org/html/rfc3986#appendix-A
.. _for IRIs: http://tools.ietf.org/html/rfc3987#section-2.2

"""
__version__ = '1.2.1'

try:
    import regex
except ImportError:
    from warnings import warn
    warn('Could not import regex. The stdlib re (at least until python 3.2) '
         'cannot compile most regular expressions in this module (reusing '
         'capture group names on different branches of an alternation).')
    del warn

__all__ = ('patterns', 'compose', 'resolve')


_common_rules = (

    ########   SCHEME   ########
    ('scheme',        u"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*)"),          # named

    ########   PORT   ########
    ('port',          u"(?P<port>[0-9]*)"),                             # named

    ########   IP ADDRESSES   ########
    ('IP_literal',  ur"\[(?:{IPv6address}|{IPvFuture})\]"),
    ('IPv6address', (u"                                (?:{h16}:){{6}} {ls32}"
                     u"|                            :: (?:{h16}:){{5}} {ls32}"
                     u"|                    {h16}?  :: (?:{h16}:){{4}} {ls32}"
                     u"| (?:(?:{h16}:)?     {h16})? :: (?:{h16}:){{3}} {ls32}"
                     u"| (?:(?:{h16}:){{,2}}{h16})? :: (?:{h16}:){{2}} {ls32}"
                     u"| (?:(?:{h16}:){{,3}}{h16})? :: (?:{h16}:)      {ls32}"
                     u"| (?:(?:{h16}:){{,4}}{h16})? ::                 {ls32}"
                     u"| (?:(?:{h16}:){{,5}}{h16})? ::                 {h16} "
                     u"| (?:(?:{h16}:){{,6}}{h16})? ::                       "
                     ).replace(' ', '')),
    ('ls32',         u"(?:{h16}:{h16}|{IPv4address})"),
    ('h16',          u"[0-9A-F]{{1,4}}"),
    ('IPv4address', ur"(?:(?:{dec_octet}\.){{3}}{dec_octet})"),
    ('dec_octet',    u"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"),
    ('IPvFuture',   ur"v[0-9A-F]+\.(?:{unreserved}|{sub_delims}|:)+"),

    ########  CHARACTER CLASSES   ########
    ('unreserved',    u"[a-zA-Z0-9_.~-]"),
    ('reserved',      u"(?:{gen_delims}|{sub_delims})"),
    ('pct_encoded',  ur"%[0-9A-F][0-9A-F]"),
    ('gen_delims',   ur"[:/?#[\]@]"),
    ('sub_delims',    u"[!$&'()*+,;=]"),

)


_uri_rules = (

    ########   REFERENCES   ########
    ('URI_reference',   u"{URI}|{relative_ref}"),
    ('URI',             ur"{absolute_URI}(?:\#{fragment})?"),
    ('absolute_URI',    ur"{scheme}:{hier_part}(?:\?{query})?"),
    ('relative_ref',   (u"(?:{relative_part}"
                        ur"(?:\?{query})?(?:\#{fragment})?)")),

    ('hier_part',      (u"(?://{authority}{path_abempty}"
                        u"|{path_absolute}|{path_rootless}|{path_empty})")),
    ('relative_part',  (u"(?://{authority}{path_abempty}"
                        u"|{path_absolute}|{path_noscheme}|{path_empty})")),

    ########   AUTHORITY   ########
    ('authority',(u"(?P<authority>"                                     # named
                  u"(?:{userinfo}@)?{host}(?::{port})?)")),
    ('host',      u"(?P<host>{IP_literal}|{IPv4address}|{reg_name})"),  # named
    ('userinfo', (u"(?P<userinfo>"                                      # named
                  u"(?:{unreserved}|{pct_encoded}|{sub_delims}|:)*)")),
    ('reg_name',  u"(?:{unreserved}|{pct_encoded}|{sub_delims})*"),

    ########   PATH   ########
    ('path',         (u"{path_abempty}|{path_absolute}|{path_noscheme}"
                      u"|{path_rootless}|{path_empty}")),
    ('path_abempty',  u"(?P<path>(?:/{segment})*)"),                    # named
    ('path_absolute', u"(?P<path>/(?:{segment_nz}(?:/{segment})*)?)"),  # named
    ('path_noscheme', u"(?P<path>{segment_nz_nc}(?:/{segment})*)"),     # named
    ('path_rootless', u"(?P<path>{segment_nz}(?:/{segment})*)"),        # named
    ('path_empty',    u"(?P<path>)"),                                   # named

    ('segment',       u"{pchar}*"),
    ('segment_nz',    u"{pchar}+"),
    ('segment_nz_nc', u"(?:{unreserved}|{pct_encoded}|{sub_delims}|@)+"),

    ########   QUERY   ########
    ('query',         ur"(?P<query>(?:{pchar}|/|\?)*)"),                # named

    ########   FRAGMENT   ########
    ('fragment',      ur"(?P<fragment>(?:{pchar}|/|\?)*)"),             # named

    ########  CHARACTER CLASSES   ########
    ('pchar',         u"(?:{unreserved}|{pct_encoded}|{sub_delims}|:|@)"),
    ('unreserved',    u"[a-zA-Z0-9._~-]"),

)


#: http://tools.ietf.org/html/rfc3987
#: January 2005
_iri_rules = (

    ########   REFERENCES   ########
    ('IRI_reference',   u"{IRI}|{irelative_ref}"),
    ('IRI',             ur"{absolute_IRI}(?:\#{ifragment})?"),
    ('absolute_IRI',    ur"{scheme}:{ihier_part}(?:\?{iquery})?"),
    ('irelative_ref',  (u"(?:{irelative_part}"
                        ur"(?:\?{iquery})?(?:\#{ifragment})?)")),

    ('ihier_part',     (u"(?://{iauthority}{ipath_abempty}"
                        u"|{ipath_absolute}|{ipath_rootless}|{ipath_empty})")),
    ('irelative_part', (u"(?://{iauthority}{ipath_abempty}"
                        u"|{ipath_absolute}|{ipath_noscheme}|{ipath_empty})")),


    ########   AUTHORITY   ########
    ('iauthority',(u"(?P<iauthority>"                                   # named
                   u"(?:{iuserinfo}@)?{ihost}(?::{port})?)")),
    ('iuserinfo', (u"(?P<iuserinfo>"                                    # named
                   u"(?:{iunreserved}|{pct_encoded}|{sub_delims}|:)*)")),
    ('ihost',      u"(?P<ihost>{IP_literal}|{IPv4address}|{ireg_name})"),#named

    ('ireg_name',  u"(?:{iunreserved}|{pct_encoded}|{sub_delims})*"),

    ########   PATH   ########
    ('ipath',         (u"{ipath_abempty}|{ipath_absolute}|{ipath_noscheme}"
                       u"|{ipath_rootless}|{ipath_empty}")),

    ('ipath_empty',    u"(?P<ipath>)"),                                 # named
    ('ipath_rootless', u"(?P<ipath>{isegment_nz}(?:/{isegment})*)"),    # named
    ('ipath_noscheme', u"(?P<ipath>{isegment_nz_nc}(?:/{isegment})*)"), # named
    ('ipath_absolute', u"(?P<ipath>/(?:{isegment_nz}(?:/{isegment})*)?)"),#named
    ('ipath_abempty',  u"(?P<ipath>(?:/{isegment})*)"),                 # named

    ('isegment_nz_nc', u"(?:{iunreserved}|{pct_encoded}|{sub_delims}|@)+"),
    ('isegment_nz',    u"{ipchar}+"),
    ('isegment',       u"{ipchar}*"),

    ########   QUERY   ########
    ('iquery',    ur"(?P<iquery>(?:{ipchar}|{iprivate}|/|\?)*)"),       # named

    ########   FRAGMENT   ########
    ('ifragment', ur"(?P<ifragment>(?:{ipchar}|/|\?)*)"),               # named

    ########   CHARACTER CLASSES   ########
    ('ipchar',      u"(?:{iunreserved}|{pct_encoded}|{sub_delims}|:|@)"),
    ('iunreserved', u"(?:[a-zA-Z0-9._~-]|{ucschar})"),
    ('iprivate', u"[\uE000-\uF8FF\U000F0000-\U000FFFFD\U00100000-\U0010FFFD]"),
    ('ucschar', (u"[\xA0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF"
                 u"\U00010000-\U0001FFFD\U00020000-\U0002FFFD"
                 u"\U00030000-\U0003FFFD\U00040000-\U0004FFFD"
                 u"\U00050000-\U0005FFFD\U00060000-\U0006FFFD"
                 u"\U00070000-\U0007FFFD\U00080000-\U0008FFFD"
                 u"\U00090000-\U0009FFFD\U000A0000-\U000AFFFD"
                 u"\U000B0000-\U000BFFFD\U000C0000-\U000CFFFD"
                 u"\U000D0000-\U000DFFFD\U000E1000-\U000EFFFD]")),

)

#: mapping of rfc3986 / rfc3987 rule names to regular expressions
patterns = {}
for name, rule in _common_rules[::-1] + _uri_rules[::-1] + _iri_rules[::-1]:
    patterns[name] = rule.format(**patterns)
del name, rule


def _get_compiled_pattern(template='^%(IRI_reference)s$'):
    c = _get_compiled_pattern._cache
    if template not in c:
        c[template] = regex.compile(template % patterns)
    return c[template]
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

    If `return_parts` is True, returns a dict of named parts instead of
    a string.
    
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
        ...     }.iteritems():
        ...     assert resolve(base, relative) == resolved

        
    .. _Resolves: http://tools.ietf.org/html/rfc3986#section-5.2

    """
    #base = normalize(base)
    if isinstance(base, basestring):
        m = _get_compiled_pattern('^%(IRI)s$').match(base)
        if not m:
            raise ValueError('Invalid base IRI %r.' % base)
        B = m.groupdict()
    _i2u(B)
    if not B.get('scheme'):
        raise ValueError('Expected an IRI (with scheme), not %r.' % base)
    
    if isinstance(uriref, basestring):
        m = _get_compiled_pattern('%(IRI_reference)s$').match(uriref)
        if not m:
            raise ValueError('Invalid IRI reference %r.' % uriref)
        R = m.groupdict()
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
        print 'Valid arguments are "--all" or rule names from'
        print '  '.join(sorted(patterns))
    elif sys.argv[1] == '--all':
        for name in patterns:
            print name, ':\n', repr(patterns[name]).strip('u')[1:-1], '\n'
    else:
        for name in sys.argv[1:]:
            print repr(patterns[name]).strip('u')[1:-1]
