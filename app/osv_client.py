# app/osv_client.py
"""Google OSV (Open Source Vulnerabilities) API Client v1.6+."""
import logging
import httpx
from typing import Dict, Any, List, Optional, Set

logger = logging.getLogger("vulnerability-lifecycle-osv")

OSV_API_URL = "https://api.osv.dev/v1/query"

_osv_cache: Dict[str, Dict[str, Any]] = {}

async def query_osv_vulnerabilities(package_name: str, version: str, ecosystem: str = "Maven") -> List[Dict[str, Any]]:
    """Queries Google OSV schema v1.6+ API for package vulnerability data.
    
    Ecosystems supported: 'Maven', 'npm', 'PyPI', 'Go'.
    """
    cache_key = f"{ecosystem}:{package_name}:{version}"
    if cache_key in _osv_cache:
        logger.info(f"OSV Client: Returning cached result for {cache_key}")
        return _osv_cache[cache_key].get("vulns", [])

    payload = {
        "version": version,
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        }
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(OSV_API_URL, json=payload)
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulns", [])
                _osv_cache[cache_key] = {"vulns": vulns}
                logger.info(f"OSV Client: Retrived {len(vulns)} OSV vulnerability records for {package_name}:{version}")
                return vulns
            else:
                logger.warning(f"OSV API returned status code {response.status_code} for {package_name}")
                return []
    except Exception as e:
        logger.error(f"Failed to query Google OSV API for {package_name}: {e}")
        return []

def is_version_affected_by_osv(osv_record: Dict[str, Any], current_version: str) -> bool:
    """Evaluates Google OSV v1.6+ affected range events against current version."""
    affected_list = osv_record.get("affected", [])
    for affected in affected_list:
        ranges = affected.get("ranges", [])
        for r in ranges:
            events = r.get("events", [])
            introduced = None
            fixed = None
            for event in events:
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    fixed = event["fixed"]
            
            # Simple version comparison check
            if introduced and current_version >= introduced:
                if fixed is None or current_version < fixed:
                    return True
    return False
