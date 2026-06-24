"""MaxMind GeoLite2 GeoIP enrichment.

Loads the GeoLite2-City MMDB file at startup.  If the file is not present
(common in dev environments) the enricher returns None/None silently and
logs a one-time warning.

Download the free GeoLite2-City.mmdb from MaxMind (requires free account)
and set GEOIP_DB_PATH in your .env file.
"""

from __future__ import annotations

import os
import structlog

log = structlog.get_logger()

_warned = False


class GeoIPEnricher:
    """Thin wrapper around geoip2.database.Reader."""

    def __init__(self, db_path: str) -> None:
        self._reader = None
        if not db_path or not os.path.exists(db_path):
            global _warned
            if not _warned:
                log.warning("geoip_db_missing", path=db_path,
                            hint="Download GeoLite2-City.mmdb and set GEOIP_DB_PATH")
                _warned = True
            return
        try:
            import geoip2.database  # type: ignore
            self._reader = geoip2.database.Reader(db_path)
            log.info("geoip_db_loaded", path=db_path)
        except Exception as exc:
            log.error("geoip_db_load_error", exc=str(exc))

    def lookup(self, ip: str) -> tuple[str | None, str | None]:
        """Return (country_name, city_name) for the given IP.

        Returns (None, None) if no reader or the IP is not found (private,
        reserved, or absent from the database).
        """
        if self._reader is None or not ip:
            return None, None
        try:
            response = self._reader.city(ip)
            country = response.country.name
            city = response.city.name
            return country, city
        except Exception:
            return None, None

    def close(self) -> None:
        if self._reader is not None:
            self._reader.close()
