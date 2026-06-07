
from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path

logger = logging.getLogger("picosentry.maven_utils")


_MAVEN_NS = "http://maven.apache.org/POM/4.0.0"
_NS = {"mvn": _MAVEN_NS}


_GRADLE_DEP_SIMPLE_RE = re.compile(
    r"^\s*(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testCompileOnly|testRuntimeOnly|annotationProcessor|compile|testCompile|runtime)\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]"
)
_GRADLE_DEP_PROJECT_RE = re.compile(
    r"^\s*(?:implementation|api|compileOnly|runtimeOnly)\s+project\(['\"]([^'\"]+)['\"]\)"
)
_GRADLE_REPO_URL_RE = re.compile(
    r"^\s*maven\s*\(\s*['\"]([^'\"]+)['\"]\s*\)\s*$"
)
_GRADLE_MAVEN_BLOCK_RE = re.compile(
    r"^\s*maven\s*\{\s*$"
)
_GRADLE_URL_RE = re.compile(
    r"^\s*url\s+['\"]([^'\"]+)['\"]"
)
_GRADLE_GROUP_RE = re.compile(
    r"^\s*group\s+['\"]([^'\"]+)['\"]"
)
_GRADLE_VERSION_RE = re.compile(
    r"^\s*version\s*=\s*['\"]([^'\"]+)['\"]"
)


def detect_maven_project(target: Path) -> bool:
    if not target.is_dir():
        return False

    if (target / "pom.xml").is_file():
        return True
    if (target / "build.gradle").is_file() or (target / "build.gradle.kts").is_file():
        return True
    if (target / "mvnw").is_file() or (target / "gradlew").is_file():
        return True
    return bool((target / "settings.gradle").is_file() or (target / "settings.gradle.kts").is_file())


def _resolve_property(text: str, properties: dict[str, str]) -> str:
    if not text:
        return ""
    result = text
    for match in re.finditer(r"\$\{([^}]+)\}", text):
        prop_name = match.group(1)
        if prop_name in properties:
            result = result.replace("${" + prop_name + "}", properties[prop_name])
    return result


def parse_pom_xml(target: Path) -> dict | None:
    pom_path = target / "pom.xml"
    if not pom_path.is_file():
        return None

    try:
        tree = ET.parse(pom_path)
    except (ET.ParseError, OSError) as exc:
        logger.debug("Failed to parse pom.xml: %s", exc)
        return None

    root = tree.getroot()


    def _find(tag: str, parent: ET.Element = root) -> ET.Element | None:
        result = parent.find(f"mvn:{tag}", _NS)
        if result is not None:
            return result
        return parent.find(tag)

    def _findall(tag: str, parent: ET.Element = root) -> list[ET.Element]:
        result = parent.findall(f"mvn:{tag}", _NS)
        if result:
            return result
        return parent.findall(tag)

    result: dict = {
        "group_id": "",
        "artifact_id": "",
        "version": "",
        "dependencies": [],
        "dependency_management": [],
        "repositories": [],
        "properties": {},
        "parent": None,
    }


    props_elem = _find("properties")
    if props_elem is not None:
        for prop in props_elem:
            result["properties"][prop.tag.split("}", 1)[-1]] = prop.text or ""


    parent_elem = _find("parent")
    if parent_elem is not None:
        pg = _find("groupId", parent_elem)
        pa = _find("artifactId", parent_elem)
        pv = _find("version", parent_elem)
        result["parent"] = {
            "group_id": pg.text if pg is not None else "",
            "artifact_id": pa.text if pa is not None else "",
            "version": pv.text if pv is not None else "",
        }


    gid = _find("groupId")
    if gid is not None:
        result["group_id"] = _resolve_property(gid.text or "", result["properties"])
    else:

        result["group_id"] = result["parent"]["group_id"] if result["parent"] else ""

    aid = _find("artifactId")
    if aid is not None:
        result["artifact_id"] = aid.text or ""

    ver = _find("version")
    if ver is not None:
        result["version"] = _resolve_property(ver.text or "", result["properties"])
    elif result["parent"]:
        result["version"] = result["parent"]["version"]


    deps_elem = _find("dependencies")
    if deps_elem is not None:
        for dep in _findall("dependency", deps_elem):
            d_gid = _find("groupId", dep)
            d_aid = _find("artifactId", dep)
            d_ver = _find("version", dep)
            d_scope = _find("scope", dep)
            group = _resolve_property(d_gid.text or "" if d_gid is not None else "", result["properties"])
            art = d_aid.text or "" if d_aid is not None else ""
            version = _resolve_property(d_ver.text or "" if d_ver is not None else "", result["properties"])
            scope = d_scope.text or "compile" if d_scope is not None else "compile"
            if group and art:
                result["dependencies"].append((group, art, version, scope))


    dep_mgmt = _find("dependencyManagement")
    if dep_mgmt is not None:
        deps_m = _find("dependencies", dep_mgmt)
        if deps_m is not None:
            for dep in _findall("dependency", deps_m):
                d_gid = _find("groupId", dep)
                d_aid = _find("artifactId", dep)
                d_ver = _find("version", dep)
                group = _resolve_property(d_gid.text or "" if d_gid is not None else "", result["properties"])
                art = d_aid.text or "" if d_aid is not None else ""
                version = _resolve_property(d_ver.text or "" if d_ver is not None else "", result["properties"])
                if group and art:
                    result["dependency_management"].append((group, art, version))


    repos_elem = _find("repositories")
    if repos_elem is not None:
        for repo in _findall("repository", repos_elem):
            r_id = _find("id", repo)
            r_url = _find("url", repo)
            rid = r_id.text or "" if r_id is not None else ""
            rurl = r_url.text or "" if r_url is not None else ""
            if rid and rurl:
                result["repositories"].append((rid, rurl))

    return result


def parse_gradle_build(target: Path) -> dict | None:
    gradle_path = target / "build.gradle"
    if not gradle_path.is_file():
        gradle_path = target / "build.gradle.kts"
        if not gradle_path.is_file():
            return None

    try:
        lines = gradle_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    result: dict = {
        "group": "",
        "name": "",
        "version": "",
        "dependencies": [],
        "repositories": [],
        "has_maven_publish": False,
    }

    in_repositories_block = 0
    in_dependencies_block = 0

    for line in lines:
        stripped = line.strip()


        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            continue


        if stripped == "repositories {":
            in_repositories_block = 1
            continue
        if stripped == "dependencies {":
            in_dependencies_block = 1
            continue
        if stripped == "}":
            if in_repositories_block > 0:
                in_repositories_block -= 1
            if in_dependencies_block > 0:
                in_dependencies_block -= 1
            continue


        if in_repositories_block > 0:
            url_match = _GRADLE_REPO_URL_RE.match(stripped)
            if url_match:
                result["repositories"].append(url_match.group(1))
                continue
            block_match = _GRADLE_MAVEN_BLOCK_RE.match(stripped)
            if block_match:
                continue
            url_in_block = _GRADLE_URL_RE.match(stripped)
            if url_in_block:
                result["repositories"].append(url_in_block.group(1))
                continue
            if "mavenLocal" in stripped:
                result["repositories"].append("mavenLocal")
                continue
            if "mavenCentral" in stripped:
                result["repositories"].append("https://repo1.maven.org/maven2")
                continue
            if "google" in stripped:
                result["repositories"].append("https://dl.google.com/dl/android/maven2/")
                continue
            if "jcenter" in stripped:
                result["repositories"].append("https://jcenter.bintray.com")
                continue


        if in_dependencies_block > 0:
            dep_match = _GRADLE_DEP_SIMPLE_RE.match(stripped)
            if dep_match:
                config = dep_match.group(0).split("(")[0] if "(" in dep_match.group(0) else ""
                result["dependencies"].append(
                    (dep_match.group(1), dep_match.group(2), dep_match.group(3), config)
                )
                continue


        if stripped.startswith("group "):
            grp_match = re.match(r"group\s+['\"]([^'\"]+)['\"]", stripped)
            if grp_match:
                result["group"] = grp_match.group(1)
        elif stripped.startswith("version"):
            ver_match = re.match(r"version\s*[= ]\s*['\"]([^'\"]+)['\"]", stripped)
            if ver_match:
                result["version"] = ver_match.group(1)
        elif "maven-publish" in stripped or "uploadArchives" in stripped:
            result["has_maven_publish"] = True

    return result


def get_maven_dep_identifiers(maven_data: dict) -> set[str]:
    names: set[str] = set()

    for dep in maven_data.get("dependencies", []):

        artifact_id = dep[1]
        if artifact_id:
            names.add(artifact_id)

    return names


def _is_public_repo_url(url: str) -> bool:
    public_repos = [
        "repo1.maven.org",
        "repo.maven.apache.org",
        "jcenter.bintray.com",
        "dl.google.com",
        "plugins.gradle.org",
        "jitpack.io",
    ]
    url_lower = url.lower().rstrip("/")
    return any(public in url_lower for public in public_repos)


def detect_private_maven_repository(target: Path) -> bool:

    pom_data = parse_pom_xml(target)
    if pom_data:
        for repo_id, repo_url in pom_data.get("repositories", []):
            if repo_url and not _is_public_repo_url(repo_url):
                return True


        pom_path = target / "pom.xml"
        if pom_path.is_file():
            try:
                tree = ET.parse(pom_path)
                root = tree.getroot()

                dm = root.find("mvn:distributionManagement", _NS)
                if dm is None:
                    dm = root.find("distributionManagement")
                if dm is not None:
                    return True
            except (ET.ParseError, OSError):
                pass


    gradle_data = parse_gradle_build(target)
    if gradle_data:
        for repo in gradle_data.get("repositories", []):
            if repo and repo not in ("mavenLocal",) and not _is_public_repo_url(repo):
                return True
        if gradle_data.get("has_maven_publish"):
            return True


    mvn_settings = target / ".mvn" / "settings.xml"
    if mvn_settings.is_file():
        try:
            tree = ET.parse(mvn_settings)
            root = tree.getroot()

            servers = root.find("servers")
            if servers is not None and len(servers) > 0:
                return True
            profiles = root.find("profiles")
            if profiles is not None:
                for profile in profiles:
                    repos = profile.find("repositories")
                    if repos is not None and len(repos) > 0:
                        return True
        except (ET.ParseError, OSError):
            pass

    return False
