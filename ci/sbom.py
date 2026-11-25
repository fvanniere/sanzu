#!/usr/bin/python3
"""SBOM CycloneDX 1.6 d'une application livrée en paquets Debian.

Modèle de la skill `sbom` (ai-skills-infra). Bibliothèque standard seulement,
plus python3-cyclonedx-lib et python3-jsonschema pour la validation.

Sous-commandes :

  generate        inventaire d'une vue (runtime ou build), au choix :
                  - debhelper : debian/control, substvars et arbres debian/<paquet> ;
                  - arborescence dpkg-deb : --package <racine>=<fichier control> ;
                  dépendances Debian résolues sur la base dpkg du build (candidat
                  APT sinon), contenu livré analysé (distributions Python,
                  node_modules, binaires Rust « cargo auditable », binaires Go) ;
  embed-manifest  manifeste de release livré dans le paquet, à côté de la SBOM ;
  check           validation stricte du schéma et présence des composants attendus ;
  verify-deb      extraction d'un .deb final, puis « check » sur la SBOM incluse
                  et contrôle du manifeste inclus ;
  manifest        manifeste archivé : nom, version, architecture et SHA-256 de
                  chaque .deb, SHA-256 de la SBOM et du manifeste inclus, des
                  SBOM archivées ;
  inject          .deb déjà construits (dpkg-buildpackage, script maison) :
                  SBOM des deux vues et manifeste ajoutés au paquet porteur,
                  md5sums, .changes et .buildinfo mis à jour, sorties archivées ;
                  une ligne de CI suffit (ci/sbom-inject.sh).

generate --image-root : système de fichiers d'une image de conteneur montée
(image tierce, relevée par le rôle sbom_inventory) ; paquets dpkg (status et
status.d des images distroless) ou apk, contenu hors paquets analysé comme un
arbre d'application.

Licences : distributions Python (License-Expression, classifiers, License),
paquets npm (license), paquets Debian (copyright DEP-5), paquets apk (L:).

Les dépendances d'un paquet Debian ne sont pas figées par le build : la SBOM
indique les versions résolues dans l'environnement de build (installées, sinon
candidates APT). La version réellement installée sur un hôte est relevée par
Ansible (rôle sbom_inventory) : c'est elle qui fait foi pour un déploiement.
"""

from __future__ import annotations

import argparse
import email.parser
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import struct
import tarfile
import tempfile
import uuid
import zlib
from datetime import datetime, UTC
from pathlib import Path

DISTRO = {"trixie": "debian-13", "forky": "debian-14"}
PROP = "fred-lab"  # espace de noms des propriétés CycloneDX


# --- debian/control et substvars ---------------------------------------------


def parse_control(path: Path) -> list[dict[str, str]]:
    """Paragraphes de debian/control, champs repliés réunis."""
    paragraphs: list[dict[str, str]] = []
    current: dict[str, str] = {}
    key = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.startswith("#"):
            continue
        if not raw.strip():
            if current:
                paragraphs.append(current)
            current, key = {}, None
            continue
        if raw[0] in " \t" and key:
            current[key] += " " + raw.strip()
            continue
        key, _, value = raw.partition(":")
        key = key.strip()
        current[key] = value.strip()
    if current:
        paragraphs.append(current)
    return paragraphs


def read_substvars(debian_dir: Path, package: str) -> dict[str, str]:
    values: dict[str, str] = {}
    path = debian_dir / f"{package}.substvars"
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            name, sep, value = line.partition("=")
            if sep:
                values[name.rstrip("?+")] = value.strip()
    return values


def substitute(field: str, substvars: dict[str, str]) -> str:
    return re.sub(r"\$\{([^}]+)\}", lambda m: substvars.get(m.group(1), ""), field)


def relation_alternatives(field: str) -> list[list[str]]:
    """« a (>= 1) | b, c [amd64] <!nocheck> » → [["a", "b"], ["c"]]."""
    groups = []
    for group in field.split(","):
        names = []
        for alt in group.split("|"):
            alt = re.sub(r"\([^)]*\)|\[[^]]*\]|<[^>]*>", "", alt).strip()
            if alt:
                names.append(alt.split(":", 1)[0])  # python3:any → python3
        if names:
            groups.append(names)
    return groups


def relation_constraints(field: str) -> list[list[tuple[str, str, str]]]:
    """« a (>= 1) | b » → [[("a", ">=", "1"), ("b", "", "")]] : alternatives et contrainte."""
    groups = []
    for group in field.split(","):
        alts = []
        for alt in group.split("|"):
            constraint = re.search(r"\(\s*([<>=]+)\s*([^)\s]+)\s*\)", alt)
            name = re.sub(r"\([^)]*\)|\[[^]]*\]|<[^>]*>", "", alt).strip()
            if name:
                op, wanted = (constraint.group(1), constraint.group(2)) if constraint else ("", "")
                alts.append((name.split(":", 1)[0], op, wanted))
        if alts:
            groups.append(alts)
    return groups


DPKG_OPS = {">=": "ge", "<=": "le", ">>": "gt", "<<": "lt", "=": "eq", ">": "ge", "<": "le"}


def satisfies(version: str, op: str, wanted: str) -> bool:
    if not op:
        return True
    return subprocess.run(["dpkg", "--compare-versions", version, DPKG_OPS.get(op, "ge"), wanted],
                          capture_output=True).returncode == 0


# --- base dpkg et APT ------------------------------------------------------------

DPKG_FORMAT = (
    "${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\t"
    "${Pre-Depends}\t${Depends}\t${Provides}\t${source:Package}\t"
    "${source:Version}\n"
)


class Resolver:
    """Résout les noms de paquets vers la base dpkg, sinon le candidat APT."""

    def __init__(self, image_root: Path | None = None) -> None:
        self.installed: dict[str, dict] = {}
        # Paquet virtuel → (fournisseur installé, version fournie ou « »).
        self.provides: dict[str, tuple[str, str]] = {}
        # Image montée : sa base dpkg, sans candidat APT (les sources de l'hôte
        # ne sont pas celles de l'image).
        # Système sans dpkg (image Alpine d'un build npm) : arbres seuls.
        self.offline = image_root is not None or shutil.which("dpkg-query") is None
        if image_root is not None:
            lines = image_dpkg_lines(image_root)
        elif self.offline:
            lines = []
        else:
            lines = subprocess.run(["dpkg-query", "-W", "-f", DPKG_FORMAT],
                                   check=True, capture_output=True, text=True).stdout.splitlines()
        for line in lines:
            name, version, arch, status, pre, dep, prov, src, srcv = line.split("\t")
            if not status.startswith("ii"):
                continue
            self.installed[name] = {
                "name": name, "version": version, "arch": arch,
                "depends": ", ".join(x for x in (pre, dep) if x),
                "source": src, "source_version": srcv, "resolution": "installed",
            }
            for virtual in relation_constraints(prov):
                self.provides.setdefault(virtual[0][0], (name, virtual[0][2]))
        self.cache: dict[str, dict | None] = {}

    def candidate(self, name: str) -> dict | None:
        """Candidat APT d'un paquet non installé (sources de l'environnement)."""
        if self.offline:
            return None
        if name in self.cache:
            return self.cache[name]
        proc = subprocess.run(
            ["apt-cache", "show", "--no-all-versions", name],
            capture_output=True, text=True,
        )
        record = None
        if proc.returncode == 0 and proc.stdout.strip():
            fields = parse_control_text(proc.stdout)
            if fields.get("Package") == name:
                src = fields.get("Source", name)
                srcv = fields["Version"]
                match = re.match(r"(\S+) \((.+)\)", src)
                if match:
                    src, srcv = match.groups()
                record = {
                    "name": name, "version": fields["Version"],
                    "arch": fields.get("Architecture", ""),
                    "depends": ", ".join(
                        x for x in (fields.get("Pre-Depends"), fields.get("Depends")) if x
                    ),
                    "source": src, "source_version": srcv, "resolution": "candidate",
                }
        self.cache[name] = record
        return record

    def virtual_candidate(self, name: str) -> tuple[dict, str] | None:
        """Paquet virtuel non installé (debhelper-compat, python3-cffi-backend-api-min,
        gir1.2-gobject-2.0…) : premier fournisseur d'apt-cache showpkg, avec la
        version fournie quand le Provides en déclare une."""
        if self.offline:
            return None
        proc = subprocess.run(["apt-cache", "showpkg", name], capture_output=True, text=True)
        lines = proc.stdout.split("Reverse Provides:", 1)
        for line in lines[1].splitlines() if len(lines) == 2 else []:
            match = re.match(r"(\S+) \S+(?: \(= ([^)]+)\))?", line.strip())
            if match:
                record = self.candidate(match.group(1))
                if record:
                    return record, match.group(2) or ""
        return None

    def resolve(self, alternatives: list[str] | list[tuple[str, str, str]]) -> dict | None:
        """Paquet qui satisfait la relation : une alternative installée l'emporte,
        comme pour apt, puis le candidat APT ; une version qui ne satisfait pas
        la contrainte n'est pas retenue (record « unsatisfied » si rien ne va)."""
        alts = [a if isinstance(a, tuple) else (a, "", "") for a in alternatives]
        rejected = None
        # Paquet virtuel : la contrainte porte sur la version fournie (dpkg),
        # sans contrainte n'importe quel fournisseur convient.
        for name, op, wanted in alts:
            record = self.installed.get(name)
            found = record and record["version"]
            if record is None and name in self.provides:
                provider, found = self.provides[name]
                record = self.installed[provider]
            if record and (not op or (found and satisfies(found, op, wanted))):
                return record
            rejected = rejected or (record and (name, op, wanted, found or "?"))
        for name, op, wanted in alts:
            record = self.candidate(name)
            found = record and record["version"]
            if record is None:
                virtual = self.virtual_candidate(name)
                if virtual:
                    record, found = virtual
            if record and (not op or (found and satisfies(found, op, wanted))):
                return record
            rejected = rejected or (record and (name, op, wanted, found or "?"))
        if rejected:
            name, op, wanted, found = rejected
            return {"name": name, "version": f"{op} {wanted}", "unsatisfied": found}
        return None


def image_dpkg_lines(root: Path) -> list[str]:
    """Base dpkg d'une image, au format de DPKG_FORMAT : status, et status.d/*
    des images distroless (un paragraphe par paquet, sans Status)."""
    paragraphs = []
    status = root / "var/lib/dpkg/status"
    if status.is_file():
        paragraphs += re.split(r"\n\s*\n", status.read_text(encoding="utf-8", errors="replace"))
    for path in sorted((root / "var/lib/dpkg/status.d").glob("*")):
        if path.is_file() and not path.name.endswith(".md5sums"):
            paragraphs += re.split(r"\n\s*\n", path.read_text(encoding="utf-8", errors="replace"))
    lines = []
    for paragraph in paragraphs:
        fields = parse_control_text(paragraph)
        if not fields.get("Package") or not fields.get("Version"):
            continue
        state = fields.get("Status", "install ok installed").split()
        abbrev = "ii" if state[-1:] == ["installed"] else "un"
        src, srcv = fields.get("Source", fields["Package"]), fields["Version"]
        match = re.match(r"(\S+) \((.+)\)", src)
        if match:
            src, srcv = match.groups()
        lines.append("\t".join([fields["Package"], fields["Version"], fields.get("Architecture", ""),
                                abbrev, fields.get("Pre-Depends", ""), fields.get("Depends", ""),
                                fields.get("Provides", ""), src, srcv]))
    return lines


def image_owned_files(root: Path) -> set[str]:
    """Fichiers des paquets d'une image (dpkg info/*.list, apk F:/R:), chemins relatifs."""
    owned = set()
    for path in (root / "var/lib/dpkg/info").glob("*.list"):
        owned.update(f.lstrip("/") for f in path.read_text(encoding="utf-8", errors="replace").splitlines())
    directory = ""
    for line in apk_db(root).splitlines():
        if line.startswith("F:"):
            directory = line[2:]
        elif line.startswith("R:"):
            owned.add(f"{directory}/{line[2:]}".lstrip("/"))
    return owned


def apk_db(root: Path) -> str:
    path = root / "lib/apk/db/installed"
    return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""


def apk_components(root: Path, distro: str) -> list[dict]:
    """Paquets apk d'une image Alpine : PURL pkg:apk/alpine, licence (L:)."""
    components = []
    for block in re.split(r"\n\s*\n", apk_db(root)):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if len(line) > 2 and line[1] == ":" and line[0] in "PVALo":
                fields.setdefault(line[0], line[2:])
        if not fields.get("P") or not fields.get("V"):
            continue
        purl = (f"pkg:apk/alpine/{fields['P']}@{quote(fields['V'])}"
                f"?arch={fields.get('A', '')}&distro={distro}")
        component = {"type": "library", "bom-ref": purl, "name": fields["P"],
                     "version": fields["V"], "purl": purl,
                     "properties": [{"name": f"{PROP}:apk-origin", "value": fields.get("o", fields["P"])}]}
        if fields.get("L"):
            component["licenses"] = licenses(fields["L"], [fields["L"]])
        components.append(component)
    return components


def os_release(root: Path) -> dict[str, str]:
    values = {}
    for name in ("etc/os-release", "usr/lib/os-release"):
        path = root / name
        if path.is_file():
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                key, sep, value = line.partition("=")
                if sep:
                    values[key] = value.strip().strip('"')
            break
    return values


def parse_control_text(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    key = None
    for raw in text.splitlines():
        if not raw.strip():
            break
        if raw[0] in " \t" and key:
            fields[key] += " " + raw.strip()
            continue
        key, _, value = raw.partition(":")
        fields[key] = value.strip()
    return fields


METADATA_RE = re.compile(
    r"/(dist|site)-packages/[^/]+\.(dist-info/METADATA|egg-info/PKG-INFO)$")

# Expression SPDX plausible : identifiants reliés par AND / OR / WITH. Le reste
# (« Apache 2.0 », « SEE LICENSE IN … ») est gardé comme nom de licence.
SPDX_ID = r"\(*[A-Za-z0-9][A-Za-z0-9.+-]*\)*"
SPDX_EXPRESSION = re.compile(rf"^{SPDX_ID}(?: +(?:AND|OR|WITH) +{SPDX_ID})*$")
CLASSIFIERS = {  # classifier PyPI sans ambiguïté -> identifiant SPDX
    "MIT License": "MIT", "Apache Software License": "Apache-2.0",
    "ISC License (ISCL)": "ISC", "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "Python Software Foundation License": "PSF-2.0", "The Unlicense (Unlicense)": "Unlicense",
    "MIT No Attribution License (MIT-0)": "MIT-0", "Zero-Clause BSD (0BSD)": "0BSD",
    "Boost Software License 1.0 (BSL-1.0)": "BSL-1.0",
}


def licenses(expression: str = "", names: tuple[str, ...] | list[str] = ()) -> list[dict]:
    """Champ CycloneDX « licenses » : une expression SPDX, sinon des noms."""
    expression = (expression or "").strip()
    if expression and len(expression) < 200 and SPDX_EXPRESSION.match(expression) \
            and expression.upper() not in ("UNKNOWN", "NONE", "UNLICENSED"):
        return [{"expression": expression}]
    kept = []
    for name in [expression, *names]:
        name = (name or "").strip()
        if name and "\n" not in name and len(name) <= 120 and name.upper() not in ("UNKNOWN", "NONE") \
                and name not in kept:
            kept.append(name)
    return [{"license": {"name": n}} for n in kept]


def python_metadata_licenses(text: str) -> list[dict]:
    headers = email.parser.HeaderParser().parsestr(text)
    if headers.get("License-Expression"):
        return licenses(headers["License-Expression"])
    classifiers = [c.rsplit("::", 1)[-1].strip() for c in headers.get_all("Classifier") or []
                   if c.startswith("License ::")]
    spdx = [CLASSIFIERS[c] for c in classifiers if c in CLASSIFIERS]
    if spdx:
        return licenses(" AND ".join(dict.fromkeys(spdx)))
    license_field = (headers.get("License") or "").strip()
    return licenses(license_field if "\n" not in license_field else "", classifiers)


def python_distributions(package: str, root: Path | None = None, image_root: Path | None = None,
                         skip: set[str] | None = None) -> list[tuple[str, str, str]]:
    """Distributions Python (dist-info / egg-info) d'un paquet : (nom, version,
    licences en JSON).

    Paquet installé : liste de fichiers dpkg (celle de l'image avec image_root).
    Arbre (root : debian/<paquet>, arborescence assemblée, image) : toutes
    les distributions, sauf les fichiers de skip (possédés par un paquet).
    """
    if root is not None:
        paths = [p for p in root.rglob("*") if p.is_file()
                 and not (skip and str(p.relative_to(root)) in skip)]
    elif image_root is not None:
        paths = [image_root / f.lstrip("/") for f in dpkg_files(image_root, package)]
    else:
        proc = subprocess.run(["dpkg-query", "-L", package], capture_output=True, text=True)
        paths = [Path(f) for f in proc.stdout.splitlines()]
    found = {}
    for path in paths:
        if METADATA_RE.search(str(path)) and path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            meta = parse_control_text(text)
            if meta.get("Name") and meta.get("Version"):
                found[(meta["Name"], meta["Version"])] = json.dumps(python_metadata_licenses(text))
    return sorted((n, v, lic) for (n, v), lic in found.items())


def dpkg_files(image_root: Path, package: str) -> list[str]:
    """Fichiers d'un paquet dans la base dpkg d'une image (info/<paquet>[:arch].list)."""
    info = image_root / "var/lib/dpkg/info"
    for candidate in [info / f"{package}.list", *sorted(info.glob(f"{package}:*.list"))]:
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8", errors="replace").splitlines()
    return []


def debian_copyright_licenses(root: Path, package: str) -> list[dict]:
    """Licences d'un paquet Debian : copyright au format DEP-5 (machine-readable)."""
    path = root / "usr/share/doc" / package / "copyright"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if not text.startswith("Format:"):
        return []
    main, others = [], []
    for paragraph in re.split(r"\n\s*\n", text):
        fields = parse_control_text(paragraph)
        name = fields.get("License", "").split(" ", 1)[0] if fields.get("License") else ""
        if not name or "Files" not in fields:
            continue
        (main if fields["Files"].split()[:1] == ["*"] else others).append(name)
    return licenses("", main or others[:5])


# --- CycloneDX -------------------------------------------------------------------


# Distribution des paquets dpkg : debian, sauf image d'une autre (ubuntu),
# fixée par generate --image-root d'après /etc/os-release de l'image.
VENDOR = {"name": "debian", "root": Path("/")}


def deb_purl(name: str, version: str, arch: str, dist: str) -> str:
    qualifiers = []
    if arch:
        qualifiers.append(f"arch={arch}")
    qualifiers.append(f"distro={DISTRO.get(dist, dist)}")
    return f"pkg:deb/{VENDOR['name']}/{name}@{quote(version)}?{'&'.join(qualifiers)}"


def quote(value: str) -> str:
    # purl : « : » d'une époque et « + » sont percent-encodés dans la version.
    return value.replace("%", "%25").replace(":", "%3A").replace("+", "%2B")


def pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def deb_component(record: dict, dist: str, with_python: bool) -> dict:
    purl = deb_purl(record["name"], record["version"], record["arch"], dist)
    component = {
        "type": "library",
        "bom-ref": purl,
        "name": record["name"],
        "version": record["version"],
        "purl": purl,
        "properties": [
            {"name": f"{PROP}:resolution", "value": record["resolution"]},
            {"name": f"{PROP}:debian-source", "value": record["source"]},
            {"name": f"{PROP}:debian-source-version", "value": record["source_version"]},
        ],
    }
    if record["resolution"] == "installed":
        found = debian_copyright_licenses(VENDOR["root"], record["name"])
        if found:
            component["licenses"] = found
    if with_python and record["resolution"] == "installed":
        image_root = VENDOR["root"] if VENDOR["root"] != Path("/") else None
        add_python(component, python_distributions(record["name"], image_root=image_root))
    return component


def add_python(component: dict, distributions: list[tuple[str, str, str]]) -> None:
    """Distributions Python d'un paquet Debian, en composants imbriqués (PURL pypi)."""
    nested = []
    for dist_name, dist_version, lic in distributions:
        ppurl = f"pkg:pypi/{pypi_name(dist_name)}@{quote(dist_version)}"
        child = {
            "type": "library", "bom-ref": f"{component['bom-ref']}#{ppurl}",
            "name": dist_name, "version": dist_version, "purl": ppurl,
            "properties": [{"name": f"{PROP}:packaged-by", "value": component["name"]}],
        }
        if json.loads(lic):
            child["licenses"] = json.loads(lic)
        nested.append(child)
    if nested:
        component["components"] = nested


# --- contenu livré : ce que le paquet embarque ---------------------------------


def elf_sections(data: bytes, wanted: tuple[str, ...]) -> dict[str, bytes]:
    """Sections nommées d'un ELF (32 ou 64 bits), sans dépendance externe."""
    if data[:4] != b"\x7fELF":
        return {}
    endian = "<" if data[5] == 1 else ">"
    if data[4] == 2:
        shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 0x3A)
        fmt = endian + "IIQQQQIIQQ"
    else:
        shoff = struct.unpack_from(endian + "I", data, 0x20)[0]
        shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 0x2E)
        fmt = endian + "IIIIIIIIII"
    if not shoff or shstrndx >= shnum:
        return {}
    headers = [struct.unpack_from(fmt, data, shoff + i * shentsize)[:6] for i in range(shnum)]
    strtab_offset, strtab_size = headers[shstrndx][4], headers[shstrndx][5]
    strtab = data[strtab_offset:strtab_offset + strtab_size]
    found = {}
    for name_offset, sh_type, _flags, _addr, offset, size in headers:
        name = strtab[name_offset:strtab.index(b"\0", name_offset)].decode(errors="replace")
        if name in wanted and sh_type != 8:  # SHT_NOBITS : rien sur disque
            found[name] = data[offset:offset + size]
    return found


def rust_auditable(section: bytes) -> list[dict]:
    """Crates liées (cargo auditable, section .dep-v0), dépendances de build exclues."""
    try:
        packages = json.loads(zlib.decompress(section))["packages"]
    except (zlib.error, ValueError, KeyError):
        return []
    return [p for p in packages if p.get("kind", "runtime") != "build"]


CRATE_PATH_RE = re.compile(
    rb"(?:index\.crates\.io|crates\.io|github\.com)-[0-9a-f]{16}/"
    rb"([A-Za-z0-9_-]+?)-(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?(?:\+[0-9A-Za-z.]+)?)/")


def rust_crate_paths(data: bytes) -> list[tuple[str, str]]:
    """Crates d'un binaire Rust sans inventaire auditable, lues dans les chemins
    de sources que rustc laisse dans les messages de panique. Repli : une crate
    sans panique possible n'y figure pas, d'où fred-lab:evidence=source-paths."""
    return sorted({(m.group(1).decode(), m.group(2).decode()) for m in CRATE_PATH_RE.finditer(data)})


def go_buildinfo(section: bytes) -> tuple[str, list[tuple[str, str, str]]] | None:
    """Version de Go et modules d'un binaire Go ≥ 1.18 (.go.buildinfo)."""
    start = section.find(b"\xff Go buildinf:")
    if start < 0 or not section[start + 15] & 2:  # chaînes en ligne seulement
        return None
    data, pos = section[start:], 32

    def read() -> str:
        nonlocal pos
        length, shift = 0, 0
        while True:
            byte = data[pos]
            pos += 1
            length |= (byte & 0x7F) << shift
            shift += 7
            if byte < 0x80:
                break
        value = data[pos:pos + length]
        pos += length
        return value.decode(errors="replace")

    go_version, modinfo = read(), read()
    if len(modinfo) >= 33 and modinfo[-17] == "\n":
        modinfo = modinfo[16:-16]
    modules: list[tuple[str, str, str]] = []
    for line in modinfo.splitlines():
        fields = line.split("\t")
        if fields[0] in ("mod", "dep") and len(fields) >= 3:
            modules.append((fields[0], fields[1], fields[2]))
        elif fields[0] == "=>" and len(fields) >= 3 and modules:
            kind = modules[-1][0]
            modules[-1] = (kind, fields[1], fields[2])  # module remplacé
    return go_version, modules


def npm_license(meta: dict) -> str:
    """Licence d'un package.json : « license » (SPDX), ancien format objet ou liste."""
    value = meta.get("license")
    if isinstance(value, dict):
        value = value.get("type")
    if not value and isinstance(meta.get("licenses"), list):
        value = " OR ".join(x.get("type", "") for x in meta["licenses"] if isinstance(x, dict))
    return value if isinstance(value, str) else ""


def npm_packages(tree: Path, skip: set[str] | None = None) -> list[tuple[str, str, str]]:
    """Paquets npm livrés : node_modules/<nom>/package.json et @scope/<nom>."""
    found = set()
    for manifest in tree.rglob("node_modules/**/package.json"):
        if skip and str(manifest.relative_to(tree)) in skip:
            continue
        parts = manifest.relative_to(tree).parts
        idx = len(parts) - 1 - parts[::-1].index("node_modules") if "node_modules" in parts else -1
        rest = parts[idx + 1:-1]
        if not (len(rest) == 1 or (len(rest) == 2 and rest[0].startswith("@"))):
            continue  # fichier interne d'un paquet (tests, sous-répertoires)
        try:
            meta = json.loads(manifest.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        if isinstance(meta.get("name"), str) and isinstance(meta.get("version"), str):
            found.add((meta["name"], meta["version"], npm_license(meta)))
    return sorted(found)


# Bibliothèques web copiées dans un dépôt (pas de gestionnaire de paquets) :
# bannière de licence en tête de fichier, sinon signature connue.
BANNER_RES = (
    re.compile(rb"/\*[!*]?[\s*]*([A-Za-z][\w.@/-]*)\s+v?(\d+\.\d+\.\d+[\w.+-]*)[\s|(]"),
    re.compile(rb"/\*[!*]?[\s*]*([A-Za-z][\w.@/-]*)\s*\|\s*v?(\d+\.\d+\.\d+[\w.+-]*)\s*\|"),
)
SIGNATURES = {  # nom de fichier -> (paquet npm, version dans le code minifié)
    "htmx": ("htmx.org", re.compile(rb'version:"(\d+\.\d+\.\d+[\w.-]*)"')),
}
NPM_NAMES = {  # nom de bannière -> paquet npm
    "eventcalendar": "@event-calendar/core", "htmx": "htmx.org", "jquery": "jquery",
    "lightgallery": "lightgallery", "qrious": "qrious", "alpine": "alpinejs",
}
CDN_RES = (  # scripts et feuilles de style chargés depuis un CDN
    re.compile(r"cdn\.jsdelivr\.net/npm/((?:@[\w.-]+/)?[\w.-]+)@([\w.+-]+)"),
    re.compile(r"unpkg\.com/((?:@[\w.-]+/)?[\w.-]+)@([\w.+-]+)"),
    re.compile(r"cdnjs\.cloudflare\.com/ajax/libs/([\w.-]+)/([\w.+-]+)/"),
)
CDN_SUFFIXES = {".html", ".htm", ".js", ".py", ".txt", ".jinja", ".j2", ".css", ".md"}


def web_library(path: Path) -> tuple[str, str] | None:
    """Bibliothèque JS/CSS copiée : (paquet npm, version), ou None."""
    with path.open("rb") as handle:
        head = handle.read(1024)
    for pattern in BANNER_RES:
        match = pattern.search(head)
        if match:
            name = match.group(1).decode().lower()
            return NPM_NAMES.get(name, name), match.group(2).decode()
    for key, (npm, pattern) in SIGNATURES.items():
        if key in path.name.lower():
            match = pattern.search(path.read_bytes())
            if match:
                return npm, match.group(1).decode()
    return None


def npm_purl(name: str, version: str) -> str:
    scope, _, base = name.rpartition("/")
    return f"pkg:npm/{quote(scope).replace('@', '%40') + '/' if scope else ''}{base}@{quote(version)}"


def nested(parent: dict, purl: str, name: str, version: str, props: list | None = None,
           ctype: str = "library", lic: list[dict] | None = None) -> dict:
    component = {
        "type": ctype, "bom-ref": f"{parent['bom-ref']}#{purl}", "name": name,
        "version": version, "purl": purl,
        "properties": [{"name": f"{PROP}:packaged-by", "value": parent["name"]}] + (props or []),
    }
    if lic:
        component["licenses"] = lic
    return component


# Image montée : pseudo-systèmes de fichiers, caches et documentation, sans
# composant livré.
IMAGE_SKIP_DIRS = ("proc", "sys", "dev", "run", "tmp", "var/cache", "var/lib/dpkg", "var/lib/apt",
                   "lib/apk", "usr/share/doc", "usr/share/man", "usr/share/locale", "usr/share/i18n")


def runtimes(tree: Path, owned: set[str]) -> tuple[list[tuple[dict, list[dict]]], tuple[str, ...]]:
    """Interpréteurs compilés livrés hors paquet Debian (images officielles
    python et node sous /usr/local, Python autonome d'une application) : un
    composant avec son CPE (NVD), et les chemins qu'il couvre, à ne pas
    inventorier fichier par fichier."""
    found, prefixes = [], []
    for header in sorted(tree.rglob("include/python3*/patchlevel.h")):
        rel = str(header.relative_to(tree))
        match = re.search(r'#define PY_VERSION\s+"([^"]+)"', header.read_text(errors="replace"))
        if rel in owned or not match:
            continue
        version = match.group(1)
        short = ".".join(version.split(".")[:2])
        base = str(header.parent.parent.parent.relative_to(tree))  # <préfixe>/include/pythonX.Y
        base = "" if base == "." else base + "/"
        found.append(({"name": "python", "version": version, "purl": f"pkg:generic/python@{version}",
                       "cpe": f"cpe:2.3:a:python:python:{version}:*:*:*:*:*:*:*", "type": "framework",
                       "evidence": "/" + rel}, [{"expression": "PSF-2.0"}]))
        prefixes += [f"{base}bin/python{short}", f"{base}lib/libpython{short}", f"{base}lib/libpython3.so",
                     f"{base}lib/python{short}/"]
    for header in sorted(tree.rglob("include/node/node_version.h")):
        rel = str(header.relative_to(tree))
        text = header.read_text(errors="replace")
        parts = [re.search(rf"#define NODE_{k}_VERSION (\d+)", text) for k in ("MAJOR", "MINOR", "PATCH")]
        if rel in owned or not all(parts):
            continue
        version = ".".join(m.group(1) for m in parts)
        base = str(header.parent.parent.parent.relative_to(tree))
        base = "" if base == "." else base + "/"
        found.append(({"name": "node", "version": version, "purl": f"pkg:generic/node@{version}",
                       "cpe": f"cpe:2.3:a:nodejs:node.js:{version}:*:*:*:*:*:*:*", "type": "framework",
                       "evidence": "/" + rel}, [{"expression": "MIT"}]))
        prefixes += [f"{base}bin/node", f"{base}include/node/"]
    return found, tuple(prefixes)


def tree_files(tree: Path, skip: set[str] | None, prefixes: tuple[str, ...] = ()) -> list[Path]:
    """Fichiers ordinaires d'un arbre, hors fichiers possédés par un paquet (skip)
    ou couverts par un composant déjà relevé (prefixes)."""
    files = []
    for path in tree.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        rel = str(path.relative_to(tree))
        if rel.startswith(prefixes) or (skip is not None and (rel in skip or rel.startswith(IMAGE_SKIP_DIRS))):
            continue
        files.append(path)
    return sorted(files)


def add_embedded(component: dict, tree: Path, with_python: bool, skip: set[str] | None = None) -> None:
    """Composants embarqués par un paquet construit ici (arbre du paquet), ou
    contenu d'une image hors de ses paquets (skip : fichiers des paquets)."""
    children: dict[str, dict] = {}
    if with_python:
        for name, version, lic in python_distributions(component["name"], tree, skip=skip):
            purl = f"pkg:pypi/{pypi_name(name)}@{quote(version)}"
            children[purl] = nested(component, purl, name, version, lic=json.loads(lic))
    for name, version, lic in npm_packages(tree, skip):
        purl = npm_purl(name, version)
        children[purl] = nested(component, purl, name, version, lic=licenses(lic))
    for manifest_path in tree.rglob("ansible_collections/*/*/MANIFEST.json"):
        # Collection Ansible (Galaxy) : pas de type purl normalisé, generic.
        try:
            info = json.loads(manifest_path.read_text(encoding="utf-8"))["collection_info"]
        except (ValueError, KeyError, OSError):
            continue
        name = f"{info['namespace']}.{info['name']}"
        purl = f"pkg:generic/{name}@{quote(info['version'])}?type=ansible-collection"
        children[purl] = nested(component, purl, name, info["version"], [
            {"name": f"{PROP}:ecosystem", "value": "ansible-galaxy"}],
            lic=licenses(" AND ".join(info.get("license") or [])))
    found, prefixes = runtimes(tree, skip or set())
    for runtime, lic in found:
        child = nested(component, runtime["purl"], runtime["name"], runtime["version"],
                       [{"name": f"{PROP}:evidence", "value": runtime["evidence"]}], runtime["type"], lic)
        child["cpe"] = runtime["cpe"]
        children[runtime["purl"]] = child
    files = tree_files(tree, skip, prefixes)
    for path in files:
        parts = path.relative_to(tree).parts
        if "node_modules" in parts or parts[:1] == ("DEBIAN",):
            continue
        rel = "/" + str(path.relative_to(tree))
        if path.suffix in (".js", ".css", ".mjs"):
            found = web_library(path)
            if found:
                purl = npm_purl(*found)
                children.setdefault(purl, nested(component, purl, found[0], found[1], [
                    {"name": f"{PROP}:evidence", "value": "banner"},
                    {"name": f"{PROP}:file", "value": rel}]))
        if path.suffix in CDN_SUFFIXES and path.stat().st_size < 2_000_000:
            text = path.read_text(encoding="utf-8", errors="ignore")
            for pattern in CDN_RES:
                for match in pattern.finditer(text):
                    name, version = match.group(1), match.group(2)
                    if not re.match(r"\d", version):
                        continue  # @latest, @next : version non figée
                    purl = npm_purl(name, version)
                    children.setdefault(purl, nested(component, purl, name, version, [
                        {"name": f"{PROP}:delivery", "value": "cdn"},
                        {"name": f"{PROP}:file", "value": rel}]))
    for path in files:
        parts = path.relative_to(tree).parts
        if parts[:1] == ("DEBIAN",):
            continue
        # Bibliothèques compilées d'une distribution Python ou d'un paquet npm :
        # déjà inventoriées par leur distribution, pas en composant opaque.
        if {"site-packages", "dist-packages", "node_modules"} & set(parts):
            continue
        with path.open("rb") as handle:
            if handle.read(4) != b"\x7fELF":
                continue
        data = path.read_bytes()
        rel = "/" + str(path.relative_to(tree))
        sections = elf_sections(data, (".dep-v0", ".go.buildinfo"))
        identified = False
        for crate in rust_auditable(sections.get(".dep-v0", b"")):
            purl = f"pkg:cargo/{crate['name']}@{quote(crate['version'])}"
            props = [{"name": f"{PROP}:binary", "value": rel}]
            if crate.get("source") and crate["source"] != "crates.io":
                props.append({"name": f"{PROP}:cargo-source", "value": crate["source"]})
            children.setdefault(purl, nested(component, purl, crate["name"], crate["version"], props))
            identified = True
        info = go_buildinfo(sections.get(".go.buildinfo", b"")) if ".go.buildinfo" in sections else None
        if info:
            go_version, modules = info
            stdlib = go_version.removeprefix("go")
            purl = f"pkg:golang/stdlib@{quote(stdlib)}"
            children.setdefault(purl, nested(component, purl, "stdlib", stdlib))
            for _kind, module, version in modules:
                purl = f"pkg:golang/{module}@{quote(version)}"
                children.setdefault(purl, nested(component, purl, module, version,
                                                 [{"name": f"{PROP}:binary", "value": rel}]))
            identified = True
        if not identified:
            for name, version in rust_crate_paths(data):
                purl = f"pkg:cargo/{name}@{quote(version)}"
                children.setdefault(purl, nested(component, purl, name, version, [
                    {"name": f"{PROP}:binary", "value": rel},
                    {"name": f"{PROP}:evidence", "value": "source-paths"}]))
                identified = True
        if not identified:
            # Binaire sans inventaire embarqué : composant opaque, identifié par
            # son empreinte (règle « binaire amont » de la skill sbom).
            ref = f"{component['bom-ref']}#file:{rel}"
            children[ref] = {
                "type": "file", "bom-ref": ref, "name": rel,
                "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(data).hexdigest()}],
                "properties": [{"name": f"{PROP}:packaged-by", "value": component["name"]},
                               {"name": f"{PROP}:opaque", "value": "true"}],
            }
    if children:
        component["components"] = [children[k] for k in sorted(children)]


def read_staged(spec: str) -> tuple[Path, dict[str, str]]:
    """« <racine>=<control> » d'un paquet assemblé pour dpkg-deb."""
    root, sep, control = spec.partition("=")
    if not sep:
        raise SystemExit(f"--package attend <racine>=<fichier control> : {spec!r}")
    return Path(root), parse_control_text(Path(control).read_text(encoding="utf-8"))


def generate(args: argparse.Namespace) -> int:
    # Paquets livrés : arbres debhelper ou arborescences dpkg-deb.
    binaries: list[dict] = []
    image_root = Path(args.image_root) if args.image_root else None
    if image_root is not None:
        # Image de conteneur tierce, montée : ses paquets (dpkg ou apk) sont
        # tous livrés ; le reste de son système de fichiers est analysé comme
        # un arbre d'application (venv, node_modules, binaires Go et Rust).
        release = os_release(image_root)
        VENDOR["name"] = release.get("ID", "debian") if release.get("ID") in ("debian", "ubuntu") else "debian"
        VENDOR["root"] = image_root
        args.dist = release.get("VERSION_CODENAME") or release.get("VERSION_ID") or args.dist
        DISTRO.setdefault(args.dist, f"{release.get('ID', 'linux')}-{release.get('VERSION_ID', '')}".rstrip("-"))
        args.installed = True
        args.app_tree = [str(image_root)]
    if args.app_tree:
        # Image de conteneur : l'application n'est pas un paquet Debian. Ses
        # arbres (venv, code, fichiers statiques) sont analysés et rattachés à
        # un composant application ; les paquets Debian de l'image viennent
        # de --installed.
        version = args.app_version or "unknown"
        source_name = args.app
        source = {}
        build_field = args.build_roots
    elif args.package:
        for spec in args.package:
            tree, control = read_staged(spec)
            binaries.append({**control, "tree": tree, "depends_field": ", ".join(
                control.get(k, "") for k in ("Pre-Depends", "Depends"))})
        version = binaries[0]["Version"]
        source_name = args.app or binaries[0].get("Source", binaries[0]["Package"]).split()[0]
        source: dict[str, str] = {}
        build_field = args.build_roots
    else:
        debian_dir = Path(args.debian_dir)
        paragraphs = parse_control(debian_dir / "control")
        source = paragraphs[0]
        version = subprocess.run(
            ["dpkg-parsechangelog", "-l", str(debian_dir / "changelog"), "-S", "Version"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        for binary in paragraphs[1:]:
            substvars = read_substvars(debian_dir, binary["Package"])
            binaries.append({**binary, "Version": version, "tree": debian_dir / binary["Package"],
                             "depends_field": ", ".join(
                                 substitute(binary.get(k, ""), substvars)
                                 for k in ("Pre-Depends", "Depends"))})
        source_name = args.app or source["Source"]
        # Vue de construction : Build-Depends* plus build-essential, implicite.
        build_field = ", ".join(
            source.get(k, "") for k in ("Build-Depends", "Build-Depends-Indep", "Build-Depends-Arch")
        ) + ", build-essential"
    app_version = args.app_version or version
    # Paquets frères : construits par le même pipeline à la même version, mais
    # inventoriés à part (un appel par paquet) ; ils ne sont pas sur le miroir.
    siblings = [s for s in (args.sibling or []) if s not in {b["Package"] for b in binaries}]
    own = {b["Package"] for b in binaries} | set(siblings)
    resolver = Resolver(image_root)
    dist = args.dist

    components: dict[str, dict] = {}
    dependencies: dict[str, set[str]] = {}
    unresolved: set[str] = set()
    own_refs: dict[str, str] = {}

    # Paquets internes (debian/internal-packages) : releases fred-lab publiées
    # par un autre projet, absentes des sources APT du build ; déclarés par nom
    # et projet, leur propre SBOM les décrit.
    external = dict(e.split("=", 1) if "=" in e else (e, "") for e in getattr(args, "external", None) or [])

    def walk(field: str) -> set[str]:
        refs = set()
        for alternatives in relation_constraints(field):
            if alternatives[0][0] in own:
                refs.add(own_refs[alternatives[0][0]])
                continue
            internal = next((a[0] for a in alternatives if a[0] in external), None)
            if internal:
                ref = f"pkg:deb/fred-lab/{internal}"
                refs.add(ref)
                props = [{"name": f"{PROP}:role", "value": "external"}]
                if external[internal]:
                    props.append({"name": f"{PROP}:project", "value": external[internal]})
                components.setdefault(ref, {"type": "library", "bom-ref": ref, "name": internal,
                                            "purl": ref, "properties": props})
                dependencies.setdefault(ref, set())
                continue
            record = resolver.resolve(alternatives)
            if record is None:
                unresolved.add(" | ".join(a[0] for a in alternatives))
                continue
            if "unsatisfied" in record:
                # Contrainte qu'aucune source du build ne satisfait (ex. nodejs
                # >= 24 hors Debian) : la dépendance est déclarée par sa seule
                # contrainte ; la version réelle est celle que relève l'hôte.
                ref = f"pkg:deb/debian/{record['name']}?distro={DISTRO.get(dist, dist)}"
                refs.add(ref)
                components.setdefault(ref, {
                    "type": "library", "bom-ref": ref, "name": record["name"],
                    "version": record["version"], "purl": ref,
                    "properties": [{"name": f"{PROP}:unsatisfied-constraint", "value": record["version"]},
                                   {"name": f"{PROP}:build-candidate", "value": record["unsatisfied"]}]})
                dependencies.setdefault(ref, set())
                continue
            ref = deb_purl(record["name"], record["version"], record["arch"], dist)
            refs.add(ref)
            if ref not in components:
                components[ref] = deb_component(record, dist, args.python)
                dependencies[ref] = set()
                dependencies[ref] = walk(record["depends"])
        return refs

    app_ref = f"pkg:generic/{source_name}@{quote(app_version)}"
    vcs_url = args.vcs_url or source.get("Vcs-Git", "")

    if args.view == "runtime":
        for binary in binaries:
            arch = binary.get("Architecture", args.arch)
            arch = "all" if arch == "all" else (args.arch if arch == "any" else arch)
            own_refs[binary["Package"]] = deb_purl(binary["Package"], binary["Version"], arch, dist)
        for sibling in siblings:
            ref = deb_purl(sibling, version, args.arch, dist)
            own_refs[sibling] = ref
            components[ref] = {
                "type": "library", "bom-ref": ref, "name": sibling, "version": version, "purl": ref,
                "properties": [{"name": f"{PROP}:role", "value": "sibling"}],
            }
            dependencies[ref] = set()
        roots = set()
        for binary in binaries:
            ref = own_refs[binary["Package"]]
            components[ref] = {
                "type": "application" if binary["Package"] != args.library_package else "library",
                "bom-ref": ref, "name": binary["Package"], "version": binary["Version"],
                "purl": ref,
                "properties": [{"name": f"{PROP}:role", "value": "delivered"}],
            }
            add_embedded(components[ref], binary["tree"], args.python)
            dependencies[ref] = set()
            dependencies[ref] = walk(binary["depends_field"])
            roots.add(ref)
    else:
        roots = walk(build_field)

    if args.installed:
        # Tous les paquets Debian installés (image) : chacun est livré.
        for name in sorted(resolver.installed):
            roots |= walk(name)
    if image_root is not None:
        for component in apk_components(image_root, DISTRO[args.dist]):
            components[component["bom-ref"]] = component
            dependencies[component["bom-ref"]] = set()
            roots.add(component["bom-ref"])
    owned = image_owned_files(image_root) if image_root is not None else None
    if args.app_tree:
        ref = f"{app_ref}#application"
        components[ref] = {"type": "application", "bom-ref": ref, "name": source_name,
                           "version": app_version, "properties": [
                               {"name": f"{PROP}:role", "value": "application"}]}
        merged: list[dict] = []
        for tree in args.app_tree:
            holder: dict = {"bom-ref": ref, "name": source_name}
            add_embedded(holder, Path(tree), args.python, owned)
            merged.extend(holder.get("components", []))
        unique = {c["bom-ref"]: c for c in merged}
        if unique:
            components[ref]["components"] = [unique[k] for k in sorted(unique)]
        dependencies[ref] = set()
        roots.add(ref)

    for path in args.extra or []:
        # Composants échappant à la détection (code tiers copié, bibliothèque
        # embarquée, script d'un CDN) : déclarés à la main, en CycloneDX.
        for component in json.loads(Path(path).read_text(encoding="utf-8")):
            components[component["bom-ref"]] = component
            dependencies.setdefault(component["bom-ref"], set())
            roots.add(component["bom-ref"])

    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", datetime.now(UTC).timestamp()))
    properties = [
        {"name": f"{PROP}:view", "value": args.view},
        {"name": f"{PROP}:source-commit", "value": args.commit},
        {"name": f"{PROP}:source-dirty", "value": str(args.dirty).lower()},
        {"name": f"{PROP}:debian-dist", "value": dist},
    ]
    properties += [{"name": f"{PROP}:unresolved", "value": u} for u in sorted(unresolved)]
    if args.upstream_url:
        properties.append({"name": f"{PROP}:upstream-url", "value": args.upstream_url})
    properties.append({"name": f"{PROP}:debian-version", "value": version})
    app = {
        "type": "container" if image_root is not None else "application", "bom-ref": app_ref,
        "name": source_name, "version": app_version, "purl": app_ref,
    }
    if image_root is not None:
        properties.append({"name": f"{PROP}:image-os", "value": os_release(image_root).get(
            "PRETTY_NAME", "inconnu")})
        if args.image_digest:
            app["hashes"] = [{"alg": "SHA-256", "content": args.image_digest.removeprefix("sha256:")}]
    if vcs_url:
        app["externalReferences"] = [
            {"type": "vcs", "url": vcs_url, "comment": f"commit {args.commit}"}
        ]
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(
            uuid.NAMESPACE_URL, f"{app_ref}/{args.view}/{args.commit}")),
        "version": 1,
        "metadata": {
            "timestamp": datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "lifecycles": [{"phase": "post-build" if args.view == "runtime" else "build"}],
            "tools": {"components": [{"type": "application", "name": "sbom.py",
                                      "group": "fred-lab/ai-skills-infra"}]},
            "component": app,
            "properties": properties,
        },
        "components": [components[k] for k in sorted(components)],
        "dependencies": [{"ref": app_ref, "dependsOn": sorted(roots)}] + [
            {"ref": k, "dependsOn": sorted(dependencies[k])} for k in sorted(dependencies)
        ],
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bom, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.chmod(out, 0o644)
    print(f"{out} : vue {args.view}, {len(components)} composant(s), "
          f"{len(unresolved)} non résolu(s)", file=sys.stderr)
    return 0


# --- contrôles ---------------------------------------------------------------------


def validate_schema(text: str) -> None:
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    error = JsonStrictValidator(SchemaVersion.V1_6).validate_str(text)
    if error is not None:
        raise SystemExit(f"SBOM invalide (CycloneDX 1.6) : {error}")


def all_names(components: list[dict]) -> set[str]:
    """Noms des composants, imbriqués compris ; noms PyPI aussi sous forme normalisée."""
    names = set()
    for component in components:
        names.add(component["name"])
        if component.get("purl", "").startswith("pkg:pypi/"):
            names.add(pypi_name(component["name"]))
        names |= all_names(component.get("components", []))
    return names


def check_text(text: str, args: argparse.Namespace) -> None:
    validate_schema(text)
    bom = json.loads(text)
    props = {p["name"]: p["value"] for p in bom["metadata"].get("properties", [])}
    errors = []
    # Un JSON valide peut ne contenir que le nom de l'application.
    if len(all_names(bom.get("components", []))) < 2:
        errors.append("moins de deux composants : l'inventaire est vide")
    if args.view and props.get(f"{PROP}:view") != args.view:
        errors.append(f"vue {props.get(f'{PROP}:view')!r}, attendue {args.view!r}")
    if args.require_commit and props.get(f"{PROP}:source-commit") in (None, "", "unknown"):
        errors.append("commit source absent")
    if args.require_clean and props.get(f"{PROP}:source-dirty") != "false":
        errors.append("arbre source modifié (non commité) au moment du build")
    unresolved = [p["value"] for p in bom["metadata"].get("properties", [])
                  if p["name"] == f"{PROP}:unresolved"]
    if unresolved:
        errors.append("dépendances non résolues : " + ", ".join(unresolved))
    names = all_names(bom.get("components", []))
    for name in args.expect or []:
        if name not in names and pypi_name(name) not in names:
            errors.append(f"composant attendu absent : {name}")
    for name in args.expect_absent or []:
        if name in names:
            errors.append(f"composant présent alors qu'il ne doit pas l'être : {name}")
    if errors:
        raise SystemExit("SBOM rejetée :\n  - " + "\n  - ".join(errors))
    print(f"SBOM conforme : {len(names)} composant(s), vue {props.get(f'{PROP}:view')}",
          file=sys.stderr)


def check(args: argparse.Namespace) -> int:
    check_text(Path(args.sbom).read_text(encoding="utf-8"), args)
    return 0


def deb_field(deb: Path, field: str) -> str:
    return subprocess.run(["dpkg-deb", "-f", str(deb), field],
                          check=True, capture_output=True, text=True).stdout.strip()


def embedded_sbom(deb: Path, member: str) -> bytes | None:
    """SBOM incluse dans un .deb, lue par dpkg-deb --fsys-tarfile (sans root)."""
    proc = subprocess.run(["dpkg-deb", "--fsys-tarfile", str(deb)], check=True, capture_output=True)
    with tempfile.TemporaryFile() as tmp:
        tmp.write(proc.stdout)
        tmp.seek(0)
        with tarfile.open(fileobj=tmp) as tar:
            for info in tar:
                if info.name.lstrip("./") == member.lstrip("/") and info.isfile():
                    data = tar.extractfile(info)
                    return data.read() if data else None
    return None


def sbom_member(package: str) -> str:
    return f"usr/share/{package}/sbom/runtime.cdx.json"


def manifest_member(package: str) -> str:
    return f"usr/share/{package}/sbom/manifest.json"


def verify_deb(args: argparse.Namespace) -> int:
    deb = Path(args.deb)
    package, version = deb_field(deb, "Package"), deb_field(deb, "Version")
    member = sbom_member(package)
    data = embedded_sbom(deb, member)
    if data is None:
        raise SystemExit(f"{deb.name} : SBOM absente ({member})")
    check_text(data.decode("utf-8"), args)
    digest = hashlib.sha256(data).hexdigest()
    print(f"{deb.name} : {member} sha256={digest}", file=sys.stderr)
    raw = embedded_sbom(deb, manifest_member(package))
    if raw is None:
        if args.allow_missing_manifest:
            return 0
        raise SystemExit(f"{deb.name} : manifeste absent ({manifest_member(package)})")
    included = json.loads(raw)
    errors = []
    if included["sboms"]["runtime"]["sha256"] != digest:
        errors.append("l'empreinte de la SBOM ne correspond pas au manifeste inclus")
    if not any(p["package"] == package and p["version"] == version for p in included["packages"]):
        errors.append(f"{package} {version} absent du manifeste inclus")
    if errors:
        raise SystemExit(f"{deb.name} : " + " ; ".join(errors))
    print(f"{deb.name} : {manifest_member(package)} cohérent", file=sys.stderr)
    return 0


def embed_manifest(args: argparse.Namespace) -> int:
    """Manifeste livré dans le paquet : tout le manifeste de release, sauf
    l'empreinte des .deb, qu'un fichier ne peut pas porter sur son contenant."""
    runtime_path, build_path = Path(args.runtime), Path(args.build)
    runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    build = json.loads(build_path.read_text(encoding="utf-8"))
    props = {p["name"]: p["value"] for p in runtime["metadata"].get("properties", [])}
    packages = []
    for component in runtime["components"]:
        if {"name": f"{PROP}:role", "value": "delivered"} in component.get("properties", []):
            arch = re.search(r"[?&]arch=([^&]+)", component["purl"])
            packages.append({"package": component["name"], "version": component["version"],
                             "architecture": arch.group(1) if arch else None})
    host = Path(args.out).parent.parent.name  # usr/share/<paquet>/sbom/manifest.json
    doc = {
        "schema": "fred-lab/sbom-manifest/1",
        "application": runtime["metadata"]["component"]["name"],
        "version": runtime["metadata"]["component"]["version"],
        "debian_version": props.get(f"{PROP}:debian-version"),
        "source_commit": props.get(f"{PROP}:source-commit"),
        "source_dirty": props.get(f"{PROP}:source-dirty") == "true",
        "debian_dist": props.get(f"{PROP}:debian-dist"),
        "vcs_url": next((r["url"] for r in runtime["metadata"]["component"].get("externalReferences", [])
                         if r["type"] == "vcs"), None),
        "packages": packages,
        "sboms": {
            "runtime": {"path": "/" + sbom_member(host), "sha256": sha256(runtime_path),
                        "serialNumber": runtime["serialNumber"]},
            "build": {"sha256": sha256(build_path), "serialNumber": build["serialNumber"]},
        },
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.chmod(out, 0o644)
    print(f"{out} : {len(packages)} paquet(s)", file=sys.stderr)
    return 0


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def manifest(args: argparse.Namespace) -> int:
    packages = []
    for deb in sorted(Path(p) for p in args.debs):
        name = deb_field(deb, "Package")
        entry = {
            "package": name, "version": deb_field(deb, "Version"),
            "architecture": deb_field(deb, "Architecture"),
            "file": deb.name, "sha256": sha256(deb),
        }
        data = embedded_sbom(deb, sbom_member(name))
        if data is not None:
            entry["sbom"] = {"path": "/" + sbom_member(name),
                             "sha256": hashlib.sha256(data).hexdigest()}
        included = embedded_sbom(deb, manifest_member(name))
        if included is not None:
            entry["manifest"] = {"path": "/" + manifest_member(name),
                                 "sha256": hashlib.sha256(included).hexdigest()}
        packages.append(entry)
    if not any("sbom" in p for p in packages):
        raise SystemExit("aucun paquet ne contient de SBOM runtime")
    runtime = json.loads(Path(args.runtime).read_text(encoding="utf-8"))
    props = {p["name"]: p["value"] for p in runtime["metadata"].get("properties", [])}
    doc = {
        "application": runtime["metadata"]["component"]["name"],
        "version": runtime["metadata"]["component"]["version"],
        "source_commit": props.get(f"{PROP}:source-commit"),
        "debian_dist": props.get(f"{PROP}:debian-dist"),
        "packages": packages,
        "sboms": {
            "runtime": {"file": Path(args.runtime).name, "sha256": sha256(Path(args.runtime)),
                        "serialNumber": runtime["serialNumber"]},
            "build": {"file": Path(args.build).name, "sha256": sha256(Path(args.build))},
        },
    }
    Path(args.out).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"{args.out} : {len(packages)} paquet(s)", file=sys.stderr)
    return 0


def changes_update(directory: Path, deb: Path) -> None:
    """Empreintes et taille du .deb modifié dans les .buildinfo puis les .changes
    voisins ; un .buildinfo réécrit change à son tour d'empreinte dans le .changes."""
    for buildinfo in sorted(directory.glob("*.buildinfo")):
        if sums_update(buildinfo, deb):
            for changes in sorted(directory.glob("*.changes")):
                sums_update(changes, buildinfo)
    for changes in sorted(directory.glob("*.changes")):
        sums_update(changes, deb)


def sums_update(path: Path, target: Path) -> bool:
    """Lignes de target dans les sections d'empreintes de path ; vrai si réécrit."""
    text = path.read_text(encoding="utf-8")
    if target.name not in text:
        return False
    data = target.read_bytes()
    size = str(len(data))
    sums = {"Checksums-Sha1": hashlib.sha1(data).hexdigest(),
            "Checksums-Sha256": hashlib.sha256(data).hexdigest(),
            "Checksums-Md5": hashlib.md5(data).hexdigest(), "Files": hashlib.md5(data).hexdigest()}
    out, section = [], None
    for line in text.splitlines():
        if line and line[0] not in " \t":
            section = line.split(":", 1)[0]
        elif section in sums and line.split()[-1:] == [target.name]:
            fields = line.split()
            fields[0], fields[1] = sums[section], size
            line = " " + " ".join(fields)
        out.append(line)
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"{path.name} : empreintes de {target.name} mises à jour (signature éventuelle à refaire)",
          file=sys.stderr)
    return True


def ar_members(deb: Path) -> list[str]:
    """Membres d'une archive ar (.deb), sans binutils."""
    names = []
    with deb.open("rb") as handle:
        if handle.read(8) != b"!<arch>\n":
            raise SystemExit(f"{deb} : pas une archive .deb")
        while header := handle.read(60):
            if len(header) < 60:
                break
            names.append(header[:16].decode().strip().rstrip("/"))
            size = int(header[48:58].decode().strip())
            handle.seek(size + size % 2, 1)
    return names


def upstream_version(version: str) -> str:
    """1:2.3.4-1+deb13u1 → 2.3.4 : ni époque, ni révision Debian."""
    version = version.split(":", 1)[-1]
    return version.rsplit("-", 1)[0] if "-" in version else version


def inject(args: argparse.Namespace) -> int:
    """SBOM et manifeste ajoutés à des .deb déjà construits."""
    debs = sorted(Path(d).resolve() for d in args.debs)
    if not debs:
        raise SystemExit("aucun .deb")
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0") or 0)
    with tempfile.TemporaryDirectory() as work:
        trees: dict[str, tuple[Path, Path, dict]] = {}
        for deb in debs:
            root = Path(work) / deb.name
            subprocess.run(["dpkg-deb", "-R", str(deb), str(root)], check=True)
            control = parse_control_text((root / "DEBIAN/control").read_text(encoding="utf-8"))
            trees[control["Package"]] = (deb, root, control)
        sources = {c.get("Source", c["Package"]).split()[0] for _, _, c in trees.values()}
        carrier = args.carrier or next(
            (n for n in sorted(trees) if n in sources), min(trees))
        deb, root, control = trees[carrier]
        version, arch = control["Version"], control.get("Architecture", args.arch)
        out_dir = Path(args.out_dir or deb.parent)
        base = out_dir / f"{carrier}_{version.split(':', 1)[-1]}_{arch}"
        sbom_dir = root / "usr/share" / carrier / "sbom"
        build_roots = args.build_roots
        debian_dir = Path(args.debian_dir) if args.debian_dir else None
        if debian_dir is not None and (debian_dir / "control").is_file():
            # Vue de construction : Build-Depends* du paquet source, installés
            # dans l'environnement du build, plus build-essential.
            source = parse_control(debian_dir / "control")[0]
            build_roots = ", ".join(source.get(k, "") for k in (
                "Build-Depends", "Build-Depends-Indep", "Build-Depends-Arch")) + ", build-essential"
        common = {
            "debian_dir": "debian", "dist": args.dist, "arch": arch, "commit": args.commit,
            "dirty": args.dirty, "vcs_url": args.vcs_url, "library_package": "", "python": True,
            "package": [f"{r}={r}/DEBIAN/control" for _, r, _ in trees.values()],
            "installed": False, "app_tree": None, "image_root": None, "image_digest": "",
            "sibling": args.sibling, "app": args.app or min(sources),
            "app_version": args.app_version or upstream_version(version),
            "build_roots": build_roots, "upstream_url": args.upstream_url, "extra": args.extra,
            "external": args.external,
        }
        runtime = sbom_dir / "runtime.cdx.json"
        build = Path(f"{base}.build.cdx.json")
        generate(argparse.Namespace(view="runtime", out=str(runtime), **common))
        generate(argparse.Namespace(view="build", out=str(build), **common))
        embed_manifest(argparse.Namespace(runtime=str(runtime), build=str(build),
                                          out=str(sbom_dir / "manifest.json")))
        for path in [sbom_dir.parent, sbom_dir, *sbom_dir.iterdir()]:
            os.chmod(path, 0o755 if path.is_dir() else 0o644)
            if epoch:
                os.utime(path, (epoch, epoch))
        # md5sums d'origine (conffiles exclus ou non, au choix du build) et
        # taille installée : seuls les fichiers de la SBOM s'y ajoutent.
        md5 = root / "DEBIAN/md5sums"
        added = {str(path.relative_to(root)): path for path in sbom_dir.iterdir()}
        lines = [line for line in (md5.read_text(encoding="utf-8").splitlines() if md5.is_file() else [])
                 if line.split("  ", 1)[-1] not in added]
        lines += [f"{hashlib.md5(path.read_bytes()).hexdigest()}  {rel}" for rel, path in sorted(added.items())]
        md5.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.chmod(md5, 0o644)
        extra = sum((path.stat().st_size + 1023) // 1024 for path in added.values()) + 1
        text = (root / "DEBIAN/control").read_text(encoding="utf-8")
        text = re.sub(r"^Installed-Size: *(\d+)$", lambda m: f"Installed-Size: {int(m.group(1)) + extra}",
                      text, flags=re.MULTILINE)
        (root / "DEBIAN/control").write_text(text, encoding="utf-8")
        data = next(m for m in ar_members(deb) if m.startswith("data.tar"))
        compression = {"data.tar.xz": "xz", "data.tar.zst": "zstd", "data.tar.gz": "gzip",
                       "data.tar": "none"}.get(data, "xz")
        owner = [] if os.geteuid() == 0 else ["--root-owner-group"]
        subprocess.run(["dpkg-deb", *owner, f"-Z{compression}", "--build", str(root), str(deb)],
                       check=True, stdout=subprocess.DEVNULL)
        changes_update(deb.parent, deb)
        install = Path(f"{base}.runtime.cdx.json")
        install.write_bytes(runtime.read_bytes())
    manifest(argparse.Namespace(runtime=str(install), build=str(build),
                                out=f"{base}.sbom-manifest.json", debs=[str(d) for d in debs]))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="inventorier une vue")
    gen.add_argument("--view", choices=("runtime", "build"), required=True)
    gen.add_argument("--debian-dir", default="debian")
    gen.add_argument("--dist", default=os.environ.get("DEBIAN_DIST", "trixie"))
    gen.add_argument("--arch", default=os.environ.get("DEB_HOST_ARCH", "amd64"))
    gen.add_argument("--commit", default=os.environ.get("SOURCE_COMMIT", "unknown"))
    gen.add_argument("--dirty", action="store_true",
                     default=os.environ.get("SOURCE_DIRTY", "false") == "true")
    gen.add_argument("--vcs-url", default=os.environ.get("SOURCE_VCS_URL", ""),
                     help="dépôt source (défaut : Vcs-Git de debian/control)")
    gen.add_argument("--library-package", default="",
                     help="paquet binaire de type bibliothèque (python3-<app>-common…)")
    gen.add_argument("--no-python", dest="python", action="store_false",
                     help="ne pas détailler les distributions Python des paquets")
    gen.add_argument("--package", action="append",
                     help="paquet assemblé pour dpkg-deb : <racine>=<fichier control> (répétable)")
    gen.add_argument("--installed", action="store_true",
                     help="image : tous les paquets Debian installés sont livrés")
    gen.add_argument("--app-tree", action="append",
                     help="image : arbre de l'application à analyser (venv, code ; répétable)")
    gen.add_argument("--sibling", action="append",
                     help="paquet frère de la même release, inventorié à part (répétable)")
    gen.add_argument("--app", default="", help="nom de l'application (défaut : source ou paquet)")
    gen.add_argument("--app-version", default=os.environ.get("UPSTREAM_VERSION", ""),
                     help="version de l'application (défaut : version Debian)")
    gen.add_argument("--build-roots", default="dpkg, gzip, coreutils",
                     help="vue build d'une arborescence dpkg-deb : outils de l'assemblage")
    gen.add_argument("--upstream-url", default=os.environ.get("UPSTREAM_URL", ""))
    gen.add_argument("--extra", action="append",
                     help="composants CycloneDX déclarés à la main (liste JSON)")
    gen.add_argument("--external", action="append",
                     help="paquet interne publié par un autre projet : <paquet>[=<projet>] (répétable)")
    gen.add_argument("--image-root", default="",
                     help="image tierce montée : ses paquets et le contenu hors paquets")
    gen.add_argument("--image-digest", default="", help="digest de l'image (sha256:…)")
    gen.add_argument("--out", required=True)
    gen.set_defaults(func=generate)

    inj = sub.add_parser("inject", help="SBOM et manifeste ajoutés à des .deb construits")
    inj.add_argument("debs", nargs="+", help=".deb d'une même release (même build)")
    inj.add_argument("--carrier", default="", help="paquet qui porte la SBOM (défaut : celui du nom du source)")
    inj.add_argument("--debian-dir", default="", help="debian/ du source : vue build = Build-Depends")
    inj.add_argument("--build-roots", default="dpkg, gzip, coreutils",
                     help="vue build sans debian/control : outils de l'assemblage")
    inj.add_argument("--out-dir", default="", help="sorties archivées (défaut : à côté des .deb)")
    inj.add_argument("--dist", default=os.environ.get("DEBIAN_DIST", "trixie"))
    inj.add_argument("--arch", default=os.environ.get("DEB_ARCH", "amd64"))
    inj.add_argument("--commit", default=os.environ.get("CI_COMMIT_SHA", "unknown"))
    inj.add_argument("--dirty", action="store_true")
    inj.add_argument("--vcs-url", default=os.environ.get("CI_PROJECT_URL", ""))
    inj.add_argument("--app", default="")
    inj.add_argument("--app-version", default="")
    inj.add_argument("--sibling", action="append", help="paquet de la release construit ailleurs")
    inj.add_argument("--upstream-url", default=os.environ.get("UPSTREAM_URL", ""))
    inj.add_argument("--extra", action="append")
    inj.add_argument("--external", action="append",
                     help="paquet interne publié par un autre projet : <paquet>[=<projet>] (répétable)")
    inj.set_defaults(func=inject)

    for name, func, target in (("check", check, "sbom"), ("verify-deb", verify_deb, "deb")):
        cmd = sub.add_parser(name)
        cmd.add_argument(target)
        cmd.add_argument("--view", choices=("runtime", "build"))
        cmd.add_argument("--expect", action="append", help="composant qui doit figurer")
        cmd.add_argument("--expect-absent", action="append", help="composant qui ne doit pas figurer")
        cmd.add_argument("--require-commit", action="store_true")
        cmd.add_argument("--require-clean", action="store_true")
        cmd.add_argument("--allow-missing-manifest", action="store_true",
                         help="verify-deb : release antérieure au manifeste inclus")
        cmd.set_defaults(func=func)

    emb = sub.add_parser("embed-manifest", help="manifeste livré dans le paquet")
    emb.add_argument("--runtime", required=True)
    emb.add_argument("--build", required=True)
    emb.add_argument("--out", required=True, help="usr/share/<paquet>/sbom/manifest.json de l'arbre")
    emb.set_defaults(func=embed_manifest)

    man = sub.add_parser("manifest")
    man.add_argument("--runtime", required=True)
    man.add_argument("--build", required=True)
    man.add_argument("--out", required=True)
    man.add_argument("debs", nargs="+")
    man.set_defaults(func=manifest)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
