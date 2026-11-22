"""Terms for optional manual infrastructure lookups."""

INFRASTRUCTURE_GLOSSARY: tuple[tuple[str, str], ...] = (
    (
        'Certificate transparency, crt.sh',
        'Public logs of certificates issued for names on the internet. crt.sh searches these logs. '
        'A listed name does not prove who owns or uses it now.',
    ),
)
