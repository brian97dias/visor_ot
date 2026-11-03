"""Reset ONLY the four VISOR OT laboratory apps, preserving user accounts.

This command uses PostgreSQL TRUNCATE ... RESTART IDENTITY RESTRICT to wipe
lab data and owned sequences atomically, including soft-deleted records.
It deliberately does NOT run Django's flush, alter auth/users, touch
django_migrations, or delete files from the passive analyzer.
"""
from django.apps import apps
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError, connection, transaction


LAB_APPS = ("assets", "ingestion", "network", "vulnerabilities")
CONFIRMATION_PHRASE = "BORRAR_LABORATORIO"


def lab_models():
    """Explicit app allowlist; includes automatically generated M2M tables."""
    found = {}
    for label in LAB_APPS:
        for model in apps.get_app_config(label).get_models(
            include_auto_created=True
        ):
            opts = model._meta
            if opts.proxy or not opts.managed:
                continue
            table = opts.db_table
            if not table.startswith(f"{label}_"):
                raise CommandError(
                    f"Tabla inesperada para {label}: {table!r}. "
                    "Revisar explícitamente el alcance antes de borrar."
                )
            found[table] = model
    if not found:
        raise CommandError("No se identificaron tablas del laboratorio.")
    return dict(sorted(found.items()))


class Command(BaseCommand):
    help = (
        "Vacía únicamente los datos del laboratorio OT en PostgreSQL y "
        "reinicia sus IDs. Conserva usuarios, roles, migraciones y esquema. "
        "Sin --execute solamente muestra una vista previa."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--execute", action="store_true",
            help="Ejecutar el borrado; sin este flag no se modifica nada.",
        )
        parser.add_argument(
            "--confirm-database", dest="confirm_database",
            help="Debe coincidir exactamente con el nombre de PostgreSQL.",
        )
        parser.add_argument(
            "--confirm", dest="confirm_phrase",
            help=f"Frase literal requerida: {CONFIRMATION_PHRASE}",
        )
        parser.add_argument(
            "--backup-confirmed", action="store_true",
            help="Confirma que guardaste un respaldo recuperable previamente.",
        )

    def handle(self, *args, **options):
        model_tables = lab_models()
        database = connection.settings_dict.get("NAME")
        database_name = str(database or "")
        if not database_name:
            raise CommandError("La configuración no identifica la base de datos.")

        # A preview is safe even on SQLite: useful for tests and planning.
        with connection.cursor() as cursor:
            existing_tables = set(connection.introspection.table_names(cursor))
        missing = set(model_tables) - existing_tables
        if missing:
            raise CommandError(
                "Faltan tablas; ejecuta primero las migraciones. "
                + ", ".join(sorted(missing))
            )
        # Do not silently leave old lab tables behind. A legacy/unmanaged
        # table must be reviewed explicitly before running a destructive reset.
        unexpected = sorted(
            table for table in existing_tables
            if table.startswith(tuple(f"{app}_" for app in LAB_APPS))
            and table not in model_tables
        )
        if unexpected:
            raise CommandError(
                "Existen tablas OT fuera de la lista segura: "
                + ", ".join(unexpected)
                + ". Revisa estas tablas antes del reinicio."
            )

        counts = {
            table: model.objects.count()
            for table, model in model_tables.items()
        }
        users_before = get_user_model().objects.count()

        self.stdout.write(f"Base de datos: {database_name}")
        self.stdout.write(f"Motor: {connection.vendor}")
        self.stdout.write(f"Tablas exclusivamente de laboratorio: {len(model_tables)}")
        self.stdout.write(f"Filas del laboratorio: {sum(counts.values())}")
        self.stdout.write(f"Usuarios que se conservarán: {users_before}")
        for table, count in counts.items():
            self.stdout.write(f"  {table}: {count}")

        if not options["execute"]:
            self.stdout.write(self.style.WARNING(
                "VISTA PREVIA: no se ha borrado ningún registro."
            ))
            return

        if connection.vendor != "postgresql":
            raise CommandError(
                "El reinicio con identidades solo está habilitado para PostgreSQL."
            )
        if options["confirm_database"] != database_name:
            raise CommandError(
                "Nombre de base de datos no confirmado. "
                "Repite exactamente el mostrado en la vista previa."
            )
        if options["confirm_phrase"] != CONFIRMATION_PHRASE:
            raise CommandError(
                f"Para borrar debes indicar --confirm {CONFIRMATION_PHRASE}"
            )
        if not options["backup_confirmed"]:
            raise CommandError(
                "Primero crea un respaldo y después indica --backup-confirmed."
            )

        # RESTRICT rather than CASCADE prevents future external tables, user
        # tables or audit tables outside this allowlist from being truncated
        # accidentally. PostgreSQL rolls back TRUNCATE and sequence resets if
        # anything fails in the transaction.
        qualified = ", ".join(
            connection.ops.quote_name(table) for table in model_tables
        )
        sql = f"TRUNCATE TABLE {qualified} RESTART IDENTITY RESTRICT"
        try:
            with transaction.atomic():
                with connection.cursor() as cursor:
                    cursor.execute(sql)
                # Keep all checks inside the transaction: any anomaly rolls
                # back the TRUNCATE and its identity-sequence resets.
                if any(model.objects.exists() for model in model_tables.values()):
                    raise CommandError(
                        "El laboratorio conserva filas inesperadas; "
                        "se revirtió el reinicio."
                    )
                if get_user_model().objects.count() != users_before:
                    raise CommandError(
                        "Cambió inesperadamente el conteo de usuarios; "
                        "se revirtió el reinicio."
                    )
        except DatabaseError as error:
            raise CommandError(
                "No se completó el reinicio; PostgreSQL revirtió la operación. "
                "Puede existir una referencia desde una tabla fuera del "
                "laboratorio. No se borró ninguna tabla adicional."
            ) from error
        self.stdout.write(self.style.SUCCESS(
            "Laboratorio reiniciado. Tablas OT vacías e identificadores "
            "reiniciados. Usuarios y migraciones conservados."
        ))
