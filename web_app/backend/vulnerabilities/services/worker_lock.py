"""Non-invasive observation of the singleton NVD worker PostgreSQL lock."""
from django.db import connection

# Shared by the separate worker process and HTTP views.
ADVISORY_LOCK_ID = 7221001215


def worker_lock_held():
    """True if a worker holds its lock; False if none does; None off PostgreSQL.

    A held lock means the worker process exists, not that NVD responded.
    Reading pg_locks never acquires another advisory lock.
    """
    if connection.vendor != "postgresql":
        return None

    # bigint advisory locks use the high/low 32-bit halves and objsubid=1.
    high = str(ADVISORY_LOCK_ID >> 32)
    low = str(ADVISORY_LOCK_ID & 0xFFFFFFFF)
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT EXISTS(
                SELECT 1 FROM pg_locks
                WHERE locktype = 'advisory' AND granted
                  AND classid::text = %s
                  AND objid::text = %s
                  AND objsubid = 1
            )
            """,
            [high, low],
        )
        return bool(cursor.fetchone()[0])
