import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import create_engine, pool
from alembic import context

# Ensure backend directory is in sys.path for importing application modules
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.core.config import settings
from app.core.database import Base
import app.models  # Ensures all seven models register their metadata with Base

# Alembic Config object, providing access to values within alembic.ini
config = context.config

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Set target metadata for autogenerate support
target_metadata = Base.metadata


def get_url() -> str:
    """Retrieve the database URL securely from application settings.

    Returns:
        str: Active database connection string.
    """
    url = settings.DATABASE_URL
    if not url:
        url = config.get_main_option("sqlalchemy.url", "")
    return url


def include_object(object, name, type_, reflected, compare_to):
    """Filter schema objects during migration autogenerate.

    Appropriately handles PostgreSQL functional/expression indexes such as
    'uq_users_email_lower' so that reflection differences do not trigger
    erroneous DROP operations on subsequent comparisons.
    """
    if type_ == "index" and reflected and compare_to is None:
        if name in ("uq_users_email_lower",):
            return False
    return True


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    Configures the context with just a URL and not an Engine. Calls to
    context.execute() emit the SQL statements to the script output.
    """
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
        include_object=include_object,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    Uses an existing connection if provided in config.attributes, or creates
    an Engine from application settings and safely manages the connection lifecycle.
    """
    def do_run_migrations(connection) -> None:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            include_object=include_object,
        )

        with context.begin_transaction():
            context.run_migrations()

    connection = config.attributes.get("connection", None)

    if connection is not None:
        do_run_migrations(connection)
    else:
        connectable = create_engine(
            get_url(),
            poolclass=pool.NullPool,
        )
        with connectable.connect() as connection:
            do_run_migrations(connection)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
