# Perspicio

1. to see through something
2. to perceive or discern clearly

> "This product uses the NVD API but is not endorsed or certified by the NVD."

## Description

Perspicio is a small, hacked together Python Flask app that provides and API to take SBOMs and generate a list of CVEs.

Why isn't this a thing already?

## High Level Requirements

* NIST API Key - https://nvd.nist.gov/developers/request-an-api-key
  * Free...for now, until DOGE screws it up.
* Flask
* SQLite
* SBOMs - not super easy to find, I'm using the Python SBOM for testing
* Environment variables (.env) with at least the following:
  * NVD_API_KEY
  * SECRET_KEY

### Optional Environment Variables Defaults

* DB_FILE - perspicio.db, in current directory
* DB_BATCH_SIZE - 10000
* DEBUG - False
* DEFAULT_ITEMS_PER_PAGE = 50
* UPLOAD_FOLDER = /tmp/spdx/uploads


## Endpoints

**POST** */sbom*

Expects an SPDX JSON file. Uploads the file to the the UPLOAD_FOLDER directory. Parses the JSON file looking for CPEs in *packages -> externalRefs -> referenceCategory["Security"]*. Might not be the best way do find them.

For each CPE, using the NIST CPE API validate the CPE is real and load the information from NIST into the local database.

Tries to respect the API limits and will return a 201 if successful.

**GET** */sbom*

Returns a paginated list of SBOMs

**GET** */sbom/<int:id>/cpe*

Returns list of CPEs for a specific SBOM.

**GET** */sbom/<int:id>/cve*

Returns a paginated list of CVEs for the SBOM.

## Commands

*flask update_cves*

Using the NIST CVE API, for each CPE, pull the CVEs. This can be a long process. I respect rate limiting and use streaming to try to limit the impact.

## TODO

* CSV output
* Format checking for SPDX
* Notes for SBOMs

## References

* SPDX - https://spdx.dev
* CPEs - https://nvd.nist.gov/products/cpe
* NIST CPE API - https://nvd.nist.gov/developers/products
* CVEs - https://cve.mitre.org
* NIST CVE API - https://nvd.nist.gov/developers/vulnerabilities
