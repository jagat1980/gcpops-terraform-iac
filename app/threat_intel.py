import time
import logging
import httpx
import langsmith

logger = logging.getLogger("vulnerability-lifecycle-threat-intel")

_kev_cache = {"data": set(), "fetched_at": 0}
KEV_CACHE_TTL = 6 * 3600  # 6 hours

async def _get_cisa_kev_data(client: httpx.AsyncClient) -> set:
    """Fetches and caches the CISA KEV catalog."""
    current_time = time.time()
    if current_time - _kev_cache["fetched_at"] < KEV_CACHE_TTL and _kev_cache["data"]:
        return _kev_cache["data"]

    try:
        response = await client.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        )
        response.raise_for_status()
        data = response.json()
        
        cve_set = {v["cveID"] for v in data.get("vulnerabilities", [])}
        _kev_cache["data"] = cve_set
        _kev_cache["fetched_at"] = current_time
        return cve_set
    except Exception as e:
        logger.error(f"Failed to fetch CISA KEV catalog: {e}")
        return _kev_cache["data"]

@langsmith.traceable(name="fetch_threat_intel", run_type="tool")
async def fetch_threat_intel(finding_id: str) -> dict:
    """
    Fetches EPSS score and CISA KEV status for a given finding_id (CVE).
    Returns {"cisa_kev": bool, "epss_score": float}.
    """
    default_result = {"cisa_kev": False, "epss_score": 0.5}

    if not finding_id.upper().startswith("CVE-"):
        logger.info(f"Non-CVE finding ID {finding_id}, returning default threat intel.")
        return default_result

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            kev_data = await _get_cisa_kev_data(client)
            cisa_kev = finding_id in kev_data

            epss_response = await client.get(
                f"https://api.first.org/data/v1/epss?cve={finding_id}"
            )
            epss_response.raise_for_status()
            epss_data = epss_response.json()
            
            epss_score = 0.5
            if epss_data.get("data") and len(epss_data["data"]) > 0:
                epss_score = float(epss_data["data"][0].get("epss", 0.5))
            
            return {"cisa_kev": cisa_kev, "epss_score": epss_score}
    except Exception as e:
        logger.error(f"Failed to fetch threat intel for {finding_id}: {e}")
        return default_result
