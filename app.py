import csv
import logging
import os
from datetime import datetime, timezone
from io import StringIO
from typing import Generator, List

import orjson
import peewee
import requests
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request
from flask_peewee.db import Database
from spdx_tools.spdx.parser.json.json_parser import parse_from_file
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential
from werkzeug.utils import secure_filename

load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


DATABASE = {
    "name": os.getenv("DB_FILE", "perspicio.db"),
    "engine": "peewee.SqliteDatabase",
}
DATABASE_BATCH_SIZE = int(os.getenv("DB_BATCH_SIZE", 10000))
DEBUG = os.getenv("DEBUG", False)
SECRET_KEY = os.getenv("SECRET_KEY")
DEFAULT_ITEMS_PER_PAGE = int(os.getenv("DEFAULT_ITEMS_PER_PAGE", 50))

UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "/tmp")
ALLOWED_EXTENSIONS = {"json"}

CPE_REFERENCES = "{http://cpe.mitre.org/dictionary/2.0}references"
CPE_REFERENCE = "{http://cpe.mitre.org/dictionary/2.0}reference"
CPE_ITEM = "{http://cpe.mitre.org/dictionary/2.0}cpe-item"
CPE_TITLE = "{http://cpe.mitre.org/dictionary/2.0}title"
CPE23_ITEM = "{http://scap.nist.gov/schema/cpe-extension/2.3}cpe23-item"

NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_API_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
FIELDS = [
    "vectorString",
    "baseScore",
    "baseSeverity",
    "attackVector",
    "attackComplexity",
    "privilegesRequired",
    "userInteraction",
    "scope",
    "confidentialityImpact",
    "integrityImpact",
    "availabilityImpact",
]

app = Flask(__name__)
app.config.from_object(__name__)

db = Database(app)


class CPE(db.Model):
    cpe = peewee.CharField(unique=True)
    cpe_id = peewee.CharField()
    name = peewee.CharField()
    depcreated = peewee.BooleanField(default=False)
    modified = peewee.DateTimeField()
    created = peewee.DateTimeField()
    references = peewee.TextField()


class SBOM(db.Model):
    name = peewee.CharField()
    created = peewee.DateTimeField()
    parsed = peewee.DateTimeField()
    namespace = peewee.CharField()


class SBOMCPE(db.Model):
    sbom = peewee.ForeignKeyField(SBOM, backref="sbom_cpes")
    cpe = peewee.ForeignKeyField(CPE, backref="sbom_cpes")


class CVE(db.Model):
    cve = peewee.CharField(unique=True)
    sourceIdentifier = peewee.CharField()
    description = peewee.TextField()
    published = peewee.DateTimeField()
    lastModified = peewee.DateTimeField()
    vulnStatus = peewee.CharField()
    vectorString = peewee.CharField(null=True)
    baseScore = peewee.FloatField(null=True)
    baseSeverity = peewee.CharField(null=True)
    attackVector = peewee.CharField(null=True)
    attackComplexity = peewee.CharField(null=True)
    privilegesRequired = peewee.CharField(null=True)
    userInteraction = peewee.CharField(null=True)
    scope = peewee.CharField(null=True)
    confidentialityImpact = peewee.CharField(null=True)
    integrityImpact = peewee.CharField(null=True)
    exploitabilityScore = peewee.FloatField(null=True)
    impactScore = peewee.FloatField(null=True)
    references = peewee.TextField()
    notes = peewee.TextField(null=True)


class CVECPE(db.Model):
    cve = peewee.ForeignKeyField(CVE, backref="cve_cpes")
    cpe = peewee.ForeignKeyField(CPE, backref="cve_cpes")


class APIError(Exception):
    status_code = 400

    def __init__(self, message: str, status_code: int = 400, payload: dict = None):
        super().__init__()
        self.message = message
        self.status_code = status_code
        self.payload = payload or {}

    def to_dict(self) -> dict:
        response = dict(self.payload or ())
        response["error"] = self.message
        return response


@app.errorhandler(APIError)
def invalid_api_usage(e):
    return jsonify(e.to_dict()), e.status_code


def is_allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def is_429_error(exception: Exception) -> bool:
    """Returns True if the exception is an HTTPError with status code 429."""
    return (
        isinstance(exception, requests.exceptions.HTTPError)
        and exception.response.status_code == 429
    )


@retry(
    retry=retry_if_exception(is_429_error),  # Retry only if 429 is encountered
    wait=wait_exponential(
        multiplier=2, min=5, max=30
    ),  # Exponential backoff: 5s, 10s, 20s, up to 30s
    stop=stop_after_attempt(5),  # Stop after 5 retries
)
def load_sbom_to_database(sbom_file_path: str) -> None:
    logger.info("Loading SBOM to database")

    logger.info("Parsing SBOM file")
    with open(sbom_file_path, "rb") as f:
        sbom_json = orjson.loads(f.read())

        logger.info("Creating SBOM in database")
        sbom = SBOM.create(
            name=sbom_json["name"],
            created=sbom_json["creationInfo"]["created"],
            parsed=datetime.now(timezone.utc),
            namespace=sbom_json["documentNamespace"],
        )

        logger.info("SBOM created in database")
        logger.info("Creating SBOM CPEs in database")
        for package in sbom_json["packages"]:
            for external_ref in package["externalRefs"]:
                if external_ref["referenceCategory"] == "SECURITY":
                    logger.info(
                        f"Creating SBOM CPE for package {package['name']} with CPE {external_ref['referenceLocator']}"
                    )
                    if (
                        cpe := CPE.get_or_none(
                            cpe=external_ref["referenceLocator"],
                        )
                    ) is None:
                        logger.info(
                            f"CPE {external_ref['referenceLocator']} does not exist in database"
                        )

                        response = requests.get(
                            NVD_CPE_URL,
                            params={
                                "cpeMatchString": external_ref["referenceLocator"],
                                "resultsPerPage": 1,
                            },
                            headers={
                                "Accept": "application/json",
                                "apiKey": NVD_API_KEY,
                            },
                        )
                        logger.info(f"Response status code: {response.status_code}")
                        logger.info(f"URL: {response.url}")

                        if response.status_code == 429:  # Rate limit hit
                            raise Exception("Rate limit exceeded")

                        try:
                            response.raise_for_status()

                            data = response.json()

                            if data["totalResults"] == 0:
                                logger.info(
                                    f"No CPE data found for CPE {external_ref['referenceLocator']}"
                                )
                                continue

                            cpe = CPE()
                            cpe.cpe = data["products"][0]["cpe"]["cpeName"]
                            cpe.cpe_id = data["products"][0]["cpe"]["cpeNameId"]
                            cpe.modified = data["products"][0]["cpe"]["lastModified"]
                            cpe.created = data["products"][0]["cpe"]["created"]
                            cpe.name = data["products"][0]["cpe"]["titles"][0]["title"]
                            cpe.depcreated = data["products"][0]["cpe"]["deprecated"]

                            references = []
                            for reference in data["products"][0]["cpe"].get("refs", []):
                                references.append(reference["ref"])
                            cpe.references = ",".join(references)

                            cpe.save()
                            logger.info(
                                f"Updated CPE {cpe.cpe} with CPE ID {cpe.cpe_id}"
                            )
                        except requests.exceptions.HTTPError as e:
                            logger.error(f"Error: {e}")
                    else:
                        logger.info(
                            f"CPE {cpe.cpe} already exists for package {package['name']}"
                        )
                    SBOMCPE.create(sbom=sbom, cpe=cpe)
                    logger.info(
                        f"SBOM CPE created for package {package['name']} with CPE {cpe.cpe}"
                    )
        logger.info("SBOM CPEs created in database")


@retry(
    retry=retry_if_exception(is_429_error),  # Retry only if 429 is encountered
    wait=wait_exponential(
        multiplier=2, min=5, max=30
    ),  # Exponential backoff: 5s, 10s, 20s, up to 30s
    stop=stop_after_attempt(5),  # Stop after 5 retries
)
def get_cve_data(cpe: CPE) -> None:
    logger.info(f"Getting CVE data for CPE {cpe.cpe}")

    total_results = 0
    start_index = 0
    results_per_page = 2000
    total_results_left = 0
    has_pages_left = True

    while has_pages_left:
        logger.info(
            f"Getting CVE data for CPE {cpe.cpe} page {start_index // results_per_page + 1}"
        )
        with requests.get(
            NVD_API_CVE_URL,
            params={
                "cpeName": cpe.cpe,
                "startIndex": start_index,
                "resultsPerPage": results_per_page,
            },
            headers={"Accept": "application/json", "apiKey": NVD_API_KEY},
            stream=True,
        ) as response:

            logger.info(f"Response status code: {response.status_code}")
            logger.info(f"URL: {response.url}")

            if response.status_code == 429:  # Rate limit hit
                print("Rate limit exceeded. Retrying...")
                raise Exception("Rate limit exceeded")

            response.raise_for_status()

            buffer = b""
            for chunk in response.iter_content(chunk_size=8192):
                buffer += chunk

                try:
                    data = orjson.loads(buffer)

                    total_results = data.get("totalResults", 0)
                    start_index = data.get("startIndex", 0)
                    results_per_page = data.get("resultsPerPage", 0)
                    total_results_left = total_results - start_index
                    logger.info(
                        f"Total results: {total_results}, start index: {start_index}, results per page: "
                        "{results_per_page}, total results left: {total_results_left}"
                    )

                    if total_results_left <= 0:
                        logger.info("No more pages left")
                        has_pages_left = False
                    else:
                        start_index += results_per_page

                    for vuln in data.get("vulnerabilities", []):
                        with db.database.atomic():
                            cve = CVE.get_or_none(cve=vuln["cve"]["id"])
                            if (
                                cve is None
                                or cve.lastModified < vuln["cve"]["lastModified"]
                            ):
                                logger.info(f"Creating CVE {vuln['cve']['id']}")

                                data = {
                                    "sourceIdentifier": vuln["cve"]["sourceIdentifier"],
                                    "published": vuln["cve"]["published"],
                                    "lastModified": vuln["cve"]["lastModified"],
                                    "vulnStatus": vuln["cve"]["vulnStatus"],
                                    "description": vuln["cve"]["descriptions"][0][
                                        "value"
                                    ],
                                    "references": ",".join(vuln.get("references", [])),
                                }

                                try:
                                    data["exploitabilityScore"] = vuln["cve"][
                                        "metrics"
                                    ]["cvssMetricV31"][0]["exploitabilityScore"]
                                    data["impactScore"] = vuln["cve"]["metrics"][
                                        "cvssMetricV31"
                                    ][0]["impactScore"]

                                    for field in FIELDS:
                                        data["" + field] = vuln["cve"]["metrics"][
                                            "cvssMetricV31"
                                        ][0]["cvssData"][field]
                                except KeyError:
                                    data["notes"] = "No CVSS v3.1 data"

                                cve = CVE.create(cve=vuln["cve"]["id"], **data)

                            cve_cpe = CVECPE.get_or_none(cve=cve, cpe=cpe)
                            if cve_cpe is None:
                                CVECPE.create(cve=cve, cpe=cpe)

                    buffer = b""
                except orjson.JSONDecodeError:
                    # Keep buffering if JSON is incomplete
                    pass


def paginated_query(
    query: peewee.Query,
    model: peewee.Model,
    items_display_name: str = "items",
) -> dict:

    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", DEFAULT_ITEMS_PER_PAGE))
    offset = (page - 1) * per_page

    paginated_query = query.limit(per_page).offset(offset)
    items_list = list(paginated_query.dicts())

    total_count = model.select().count()

    return {
        "page": page,
        "per_page": per_page,
        "total": total_count,
        "total_pages": (total_count + per_page - 1) // per_page,
        items_display_name: items_list,
    }


def stream_csv(
    objs: peewee.Select, fieldnames: List[str]
) -> Generator[str, None, None]:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=fieldnames,
    )

    writer.writeheader()
    yield output.getvalue()
    output.seek(0)
    output.truncate(0)

    for obj in objs:
        writer.writerow(obj.__data__)
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)


@app.get("/sbom")
def list_sboms():
    return paginated_query(
        SBOM.select(),
        SBOM,
        "sboms",
    )


@app.post("/sbom")
def upload_sbom():
    if "file" not in request.files:
        raise APIError("Missing SBOM File", 400)

    validate = request.args.get("validate", "true").lower() == "true"
    logger.info(f"Validation: {validate}")

    file = request.files["file"]

    if file.filename == "":
        raise APIError("No selected file", 400)

    if not is_allowed_file(file.filename):
        raise APIError("Invalid file type", 400)

    if file.mimetype != "application/json":
        raise APIError("Invalid MIME type", 400)

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        logger.info(f"Saving SBOM file to {file_path}")
        with open(file_path, "wb") as f:
            for chunk in file:
                f.write(chunk)

        if validate:
            logger.info(f"Validating SBOM file {file_path}")
            spdx_document = parse_from_file(file_path)
            validation_messages = validate_full_spdx_document(spdx_document)

            if validation_messages:
                raise APIError(f"Invalid SPDX document: {validation_messages}", 400)

        load_sbom_to_database(file_path)
        return (
            jsonify(
                {
                    "message": "SBOM uploaded and processed successfully",
                }
            ),
            201,
        )

    except APIError as e:
        raise e


@app.route("/sbom/<int:sbom_id>/cpe", methods=["GET"])
def list_sbom_cpes(sbom_id: int):
    sbom = SBOM.get_or_none(SBOM.id == sbom_id)
    if sbom is None:
        return jsonify({"error": "SBOM not found"}), 404

    return {
        **{"sbom": sbom.__data__},
        **paginated_query(
            SBOMCPE.select(CPE).join(CPE).where(SBOMCPE.sbom == sbom),
            SBOMCPE,
            "sbom_cpes",
        ),
    }


@app.route("/sbom/<int:sbom_id>/cve", methods=["GET"])
def list_sbom_cves(sbom_id: int):
    output_format = request.args.get("format", "json")

    if output_format not in ["json", "csv"]:
        raise APIError("Invalid output format", 400)

    sbom = SBOM.get_or_none(SBOM.id == sbom_id)
    if sbom is None:
        raise APIError("SBOM not found", 404)

    cves = (
        CVE.select()
        .join(CVECPE)
        .join(CPE)
        .join(SBOMCPE)
        .where(SBOMCPE.sbom == sbom_id)
        .distinct()
    )

    if output_format == "csv":
        return Response(
            stream_csv(
                cves,
                CVE._meta.fields.keys(),
            ),
            content_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=sbom_cve.csv"},
        )
    else:
        return {
            **{"sbom": sbom.__data__},
            **paginated_query(cves, CVE, "cves"),
        }


@app.cli.command("update-cves")
def update_cves():
    for cpe in CPE.select():
        get_cve_data(cpe)


if __name__ == "__main__":
    logger.info("Starting Perspicio")

    CPE.create_table(fail_silently=True)
    SBOM.create_table(fail_silently=True)
    SBOMCPE.create_table(fail_silently=True)
    CVE.create_table(fail_silently=True)
    CVECPE.create_table(fail_silently=True)

    app.run()
