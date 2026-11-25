#!/usr/bin/env bash
# SBOM CycloneDX et manifeste de release (skill sbom) ajoutés à des .deb déjà
# construits, pour les dépôts dont le build n'est pas celui des modèles
# (dpkg-buildpackage, script maison, binaire amont) : une ligne en fin de job
# de build, avant les tests et la publication.
#
#   bash ci/sbom-inject.sh <répertoire des .deb> [<debian/ du source>]
#
# Pour chaque architecture du répertoire (paquets « all » joints à chacune) :
# vue livrée et vue de construction (Build-Depends* si debian/ est donné,
# sinon SBOM_BUILD_ROOTS), manifeste inclus dans le paquet porteur sous
# /usr/share/<paquet>/sbom/, md5sums, .changes et .buildinfo mis à jour, puis
# contrôle de release (verify-deb). Sorties archivées à côté des .deb, à
# publier avec eux :
#   <porteur>_<version>_<arch>.{runtime,build}.cdx.json, .sbom-manifest.json
#
# Réglages : SBOM_CARRIER (paquet porteur, défaut : celui qui porte le nom du
# source), SBOM_SIBLINGS (paquets de la release construits par un autre job),
# SBOM_BUILD_ROOTS, SBOM_APP (nom de l'application, défaut : source),
# SBOM_EXPECT / SBOM_EXPECT_ABSENT (composants attendus / interdits dans la
# vue livrée), SBOM_EXTERNAL (paquets internes publiés par un autre projet,
# « <paquet>[=<projet>] », en plus de ceux de debian/internal-packages).
set -euo pipefail
[ "${VERBOSE:-1}" != 1 ] || set -x

dir=${1:?répertoire des .deb}
debian=${2:-}
here=$(dirname "$0")

# Candidats APT à jour (dépendances non installées) ; python3 et la
# validation du schéma si l'image du build ne les a pas.
apt-get update -qq
need=()
command -v python3 >/dev/null || need+=(python3)
python3 -c 'import cyclonedx, jsonschema' 2>/dev/null || need+=(python3-cyclonedx-lib python3-jsonschema)
[ ${#need[@]} = 0 ] || apt-get install -qq -y --no-install-recommends "${need[@]}" >/dev/null

shopt -s nullglob
debs=("$dir"/*.deb)
[ ${#debs[@]} -gt 0 ] || { echo "ERREUR : aucun .deb dans $dir" >&2; exit 1; }
declare -A by_arch=()
indep=()
for deb in "${debs[@]}"; do
    arch=$(dpkg-deb -f "$deb" Architecture)
    if [ "$arch" = all ]; then indep+=("$deb"); else by_arch[$arch]+="$deb "; fi
done
[ ${#by_arch[@]} -gt 0 ] || by_arch[all]=""

# shellcheck source=/dev/null # os-release de l’environnement du build
args=(--commit "${CI_COMMIT_SHA:-unknown}" --vcs-url "${CI_PROJECT_URL:-}"
      --dist "${DEBIAN_DIST:-$(. /etc/os-release && echo "$VERSION_CODENAME")}")
[ -z "$debian" ] || args+=(--debian-dir "$debian")
[ -z "${SBOM_CARRIER:-}" ] || args+=(--carrier "$SBOM_CARRIER")
[ -z "${SBOM_APP:-}" ] || args+=(--app "$SBOM_APP")
[ -z "${SBOM_BUILD_ROOTS:-}" ] || args+=(--build-roots "$SBOM_BUILD_ROOTS")
[ -z "${UPSTREAM_VERSION:-}" ] || args+=(--app-version "$UPSTREAM_VERSION")
for sibling in ${SBOM_SIBLINGS:-}; do args+=(--sibling "$sibling"); done
# Paquets internes (absents des sources APT du build) : « <paquet> <projet> ».
internal=${debian:-debian}/internal-packages
if [ -f "$internal" ]; then
    while read -r pkg project _; do
        args+=(--external "$pkg=$project")
    done < <(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$internal")
fi
for e in ${SBOM_EXTERNAL:-}; do args+=(--external "$e"); done
check=(--view runtime --require-commit)
for e in ${SBOM_EXPECT:-}; do check+=(--expect "$e"); done
for e in ${SBOM_EXPECT_ABSENT:-}; do check+=(--expect-absent "$e"); done

for arch in "${!by_arch[@]}"; do
    # shellcheck disable=SC2206 # liste de chemins sans espace (noms de .deb)
    set_debs=(${by_arch[$arch]} "${indep[@]}")
    args_arch=()
    [ "$arch" = all ] || args_arch=(--arch "$arch")
    python3 "$here/sbom.py" inject "${set_debs[@]}" "${args[@]}" "${args_arch[@]}"
done

# Contrôle de release : SBOM et manifeste inclus dans chaque porteur.
for manifest in "$dir"/*.sbom-manifest.json; do
    base=${manifest%.sbom-manifest.json}
    mapfile -t carriers < <(python3 -c 'import json, sys
for package in json.load(open(sys.argv[1]))["packages"]:
    if "sbom" in package:
        print(package["file"])' "$manifest")
    for deb in "${carriers[@]}"; do
        python3 "$here/sbom.py" verify-deb "$(dirname "$manifest")/$deb" "${check[@]}"
    done
    python3 "$here/sbom.py" check "$base.build.cdx.json" --view build --require-commit
done
