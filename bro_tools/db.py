import datetime
import ipaddress
from itertools import chain
from pathlib import Path
import sqlite3

from .log_reader import BroLogReader


sqlite3.register_adapter(datetime.timedelta, lambda x: x.total_seconds())
sqlite3.register_adapter(ipaddress.IPv4Address, lambda x: str(x))
sqlite3.register_adapter(ipaddress.IPv6Address, lambda x: str(x))


def build_db(log_dir, database=':memory:'):
    """Read a directory of Bro logs into a sqlite3 database.

    :param log_dir: The path to the directory of logs.
    :param database: The database to use (default=':memory:')

    """
    log_dir = Path(log_dir)
    conn = sqlite3.connect(database)
    cur = conn.cursor()

    for filename in log_dir.glob('*.log'):
        with filename.open() as logfile:
            reader = BroLogReader(logfile, decompose_aggregate=False)

            # This is kinda hacky
            #
            # The way the BroLogReader works, none of the metadata is available
            # until after the first record has been read.  This reads the first
            # record and then puts it back for re-reading later.
            records = iter(reader)
            first = next(records)
            records = chain((first,), records)

            table_name = filename.stem
            fields = [f.replace('.', '_') for f in reader.fields]

            cur.execute('CREATE TABLE {} ({});'.format(
                table_name, ', '.join(fields)))
            insert = 'INSERT INTO {} VALUES ({});'.format(
                table_name, ', '.join(':{}'.format(f)
                                      for f in fields))
            for rec in records:
                rec = {k.replace('.', '_'): v for k, v in rec.items()}
                cur.execute(insert, rec)
            conn.commit()

    cur.close()

    return conn
