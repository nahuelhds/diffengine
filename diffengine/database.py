import os

from peewee import *
from playhouse.migrate import SqliteMigrator, PostgresqlMigrator, migrate
from playhouse.db_url import connect

DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL is not None:
    print("defined database. Using PostgreSQL.")
    db = connect(DATABASE_URL)
else:
    print("no database defined, using SQLite.")
    db = SqliteDatabase(None)


def setup_db():
    global db

    # If it's local, it needs to be init
    if DATABASE_URL is None:
        db_file = config.get("db", home_path("diffengine.db"))
        logging.debug("connecting to db %s", db_file)
        db.init(db_file)

    db.connect()
    db.create_tables([Feed, Entry, FeedEntry, EntryVersion, Diff], safe=True)

    # If it's local, it needs to be init
    if DATABASE_URL is None:
        try:
            migrator = SqliteMigrator(db)
            migrate(migrator.add_index("entryversion", ("url",), False))
        except OperationalError as e:
            logging.debug(e)
