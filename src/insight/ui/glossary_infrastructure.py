"""Terms for optional manual infrastructure lookups."""

INFRASTRUCTURE_GLOSSARY: tuple[tuple[str, str], ...] = (
    (
        'RDAP',
        'Registration Data Access Protocol. A way to ask a registry when a domain was registered '
        'or which range holds an address. Insight drops all personal contact details.',
    ),
    (
        'AS, ASN',
        'An autonomous system is a network with its own routing rules. Its number tells you which '
        'network announces an address. It does not tell you who used that address.',
    ),
    (
        'RIPEstat, RIPE NCC',
        'A public service from RIPE NCC that shows internet routing data. Its terms may require '
        'permission for commercial use.',
    ),
    (
        'IANA',
        'Internet Assigned Numbers Authority. It lists the registries that Insight may ask.',
    ),
    (
        'Certificate transparency, crt.sh',
        'Public logs of certificates issued for names on the internet. crt.sh searches these logs. '
        'A listed name does not prove who owns or uses it now.',
    ),
    (
        'Passive DNS, CIRCL',
        'Past records of how internet names point to addresses or other names. '
        'CIRCL is the Computer Incident Response Center Luxembourg, which shares this history with approved '
        'users. A past record does not prove who owns or uses a name now.',
    ),
)
