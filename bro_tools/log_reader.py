"""Read a Bro log.

The format for the Bro log is documented (at least somewhat) [1].

[1]: https://www.bro.org/sphinx/logs/index.html

"""

import codecs
import datetime
import ipaddress
import re


def maybe_singleton(thing):
    if len(thing) == 1:
        return thing[0]
    else:
        return thing


class BroLogFormatError(Exception):
    pass


def range_check(minv, maxv):
    if minv is not None and maxv is not None:
        def validate(val):
            val = int(val)
            if minv <= val < maxv:
                return val
            else:
                raise ValueError('{} not between {} and {}'
                                 .format(val, minv, maxv))
    elif maxv is not None:
        def validate(val):
            val = int(val)
            if val < maxv:
                return val
            else:
                raise ValueError('{} not less than {}'
                                 .format(val, maxv))
    elif minv is not None:
        def validate(val):
            val = int(val)
            if minv <= val:
                return val
            else:
                raise ValueError('{} not greater than or equal to {}'
                                 .format(val, minv))
    else:
        validate = int
    return validate


def bool_from_str(v):
    if v in {'1', 'y', 'Y', 't', 'T'}:
        return True
    if v in {'0', 'n', 'N', 'f', 'F'}:
        return False
    raise ValueError('{!r} not bool-like'.format(v))


AGGREGATE_TYPE_RE = re.compile(r'^(\w+)\[(\w+)\]$')
AGGREGATE_TYPES = {
    'set': set,
    'vector': tuple,
}

TYPES = {
    'addr': ipaddress.ip_address,
    'bool': bool_from_str,
    'count': range_check(0, None),
    'enum': lambda x: x,
    'interval': lambda x: datetime.timedelta(seconds=float(x)),
    'port': range_check(0, 2**16),
    'string': lambda x: x,
    'time': lambda x: datetime.datetime.fromtimestamp(float(x)),
}


class BroLogReader(object):
    """Read a Bro logfile.

    :param logfile: A file object opened on the log.
    :param decompose_aggregate: Should aggregate types (set and vector)
                                be returned as Python sets or lists
                                (respectively) or as unmodified strings?

    This reads the log in accordance with the header.
    It is iterable, each value is a dict of the data.
    Unset fields get the value ``None``.

    The log metadata is available as properties on this object.
    Interesting metadata include

    *  ``open``, the time the log was opened;
    *  ``close``, the time the log was closed;
    *  ``path``, the name of the log.

    """

    def __init__(self, logfile, *, decompose_aggregate=True):
        self._logfile = logfile
        self._decompose_aggregate = decompose_aggregate

        self._metadata = {'separator': ' '}

    def __getattr__(self, name):
        try:
            return self._metadata[name]
        except KeyError:
            raise AttributeError(name)

    def _cast_value(self, value, type_):
        if value == self.unset_field:
            return None

        m = AGGREGATE_TYPE_RE.match(type_)
        if m:
            agg_type = m.group(1)
            subtype = m.group(2)

            if self._decompose_aggregate:
                if value == self.empty_field:
                    return AGGREGATE_TYPES[agg_type]()
                else:
                    return AGGREGATE_TYPES[agg_type](
                        self._cast_value(v, subtype)
                        for v in value.split(self.set_separator))
            else:
                return value
        else:
            return TYPES[type_](value)

    def _cast_values(self, values, types):
        return [self._cast_value(v, t) for v, t in zip(values, types)]

    def __iter__(self):
        for line in self._logfile:
            if line.startswith('#'):
                # metadata line
                key, *rest = line.lstrip('#').rstrip('\n').split(
                    self.separator)
                rest = maybe_singleton(tuple(rest))

                if key in {'separator', 'set_separator'}:
                    rest = codecs.decode(rest, 'unicode_escape')
                    if len(rest) != 1:
                        raise BroLogFormatError(
                            '"{!r}" is not a valid separator'.format(rest))
                elif key in {'open', 'close'}:
                    rest = datetime.datetime(*(int(p)
                                               for p in rest.split('-')))

                self._metadata[key] = rest
            else:
                values = self._cast_values(
                    line.rstrip('\n').split(self.separator),
                    self._metadata['types'])
                yield dict(zip(self.fields, values))


if __name__ == '__main__':
    import pprint
    import sys

    reader = BroLogReader(open(sys.argv[1], 'rt'))
    for r in reader:
        pprint.pprint(r)

    pprint.pprint(reader._metadata)
