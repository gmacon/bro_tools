# bro_tools

Some tools for working with Bro logs in Python

Right now, there are just two things here:

- `log_reader`, which reads the logs and yields the entries one at a time
- `db`, which reads a directory full of logs into a dynamically-created
  SQLite database for your querying pleasure.
