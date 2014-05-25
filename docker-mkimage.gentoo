#! /usr/bin/env bash

# Gentoo verified docker deployment
# (c) 2014 Daniel Golle, updates (c) 2014 Stuart Shelton
#
# Requirements: wget/curl, GnuPG, OpenSSL, docker.io ;)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Include https://github.com/srcshelton/stdlish.sh.git::stdlib.sh, if
# available...
#
std_LIB="stdlib.sh"
for std_LIBPATH in \
	"." \
	"$( dirname "$( type -pf "${std_LIB}" 2>/dev/null )" )" \
	"$( readlink -e "$( dirname -- "${BASH_SOURCE:-${0:-.}}" )/../lib" )" \
	"/usr/local/lib" \
	 ${FPATH:+${FPATH//:/ }} \
	 ${PATH:+${PATH//:/ }}
do
	if [[ -r "${std_LIBPATH}/${std_LIB}" ]]; then
		break
	fi
done
[[ -r "${std_LIBPATH}/${std_LIB}" ]] && source "${std_LIBPATH}/${std_LIB}" || {
	echo >&2 "FATAL:  Unable to source ${std_LIB} functions"
	exit 1
}

std::vcmp "${std_RELEASE}" -ge "1.4" || \
	die "${NAME:-${0}} requires a more recent stdlib.sh library"

std_DEBUG="${DEBUG:-0}"
std_TRACE="${TRACE:-0}"
std_LOGFILE="syslog"

NAMESPACE=gentoo

PGPKEYSERVER=pgp.mit.edu
PGPPUBKEYFINGERPRINT=13EBBDBEDE7A12775DFDB1BABB572E0E2D182910

std::requires docker gpg openssl
std::requires --keep-going wget || std::requires --keep-going curl || \
	die "Cannot locate required 'curl' or 'wget' binaries"

set -o pipefail

declare -i action=1
declare -i ignore=0

function download() {
	local url mirror destination
	eval $( std::parseargs -- "${@}" ) || {
		set -- $( std::parseargs --strip -- "${@}" )
		url="${1:-}" ; shift
		mirror="${1:-}" ; shift
		destination="${1:-}" ; shift
	}

	[[ -n "${url:-}" ]] || \
		die "${FUNCNAME}: Required parameter '-url' missing"

	if [[ -n "${mirror:-}" ]]; then
		url="${mirror%%/}/${url}"
	fi

	[[ -n "${destination:-}" ]] || \
		die "${FUNCNAME}: Required parameter '-destination' missing"

	if type -pf curl >/dev/null 2>&1; then
		#curl --insecure --silent "${url}" --output "${destination}" || return 1
		curl --insecure "${url}" --output "${destination}" || return 1
	else
		#wget --no-check-certificate --quiet --output-document "${destination}" "${url}" || return 1
		wget --no-check-certificate --output-document "${destination}" "${url}" || return 1
	fi

	return 0
} # download

function downloadtext() {
	local url mirror stripcommand="cat -" filter
	local -i stripcomments=0
	eval $( std::parseargs -- "${@}" ) || {
		set -- $( std::parseargs --strip -- "${@}" )
		url="${1:-}" ; shift
		mirror="${1:-}" ; shift
		stripcomments="${1:-}" ; shift
		filter="${1:-}" ; shift
	}

	[[ -n "${url:-}" ]] || \
		die "${FUNCNAME}: Required parameter '-url' missing"

	if [[ -n "${mirror:-}" ]]; then
		url="${mirror%%/}/${url}"
	fi

	(( stripcomments )) && stripcommand="grep --line-buffered -v '^[[:space:]]*#' | sed 's/#.*$//'"
	[[ -n "${filter:-}" ]] || filter="cat -"

	respond "$( eval '{
		if type -pf curl >/dev/null 2>&1; then
			curl --insecure --silent "${url}" || return 1
		else
			wget --no-check-certificate --quiet --output-document /dev/stdout "${url}" || return 1
		fi
	} | eval ${stripcommand} | eval ${filter}' )"

	return 0
} # downloadtext

function getautobuildpath() {
	local arch
	eval $( std::parseargs -- "${@}" ) || {
		set -- $( std::parseargs --strip -- "${@}" )
		arch="${1:-}" ; shift
	}

	[[ -n "${arch:-}" ]] || \
		die "${FUNCNAME}: Required parameter '-arch' missing"

	# The x32 ABI is still an amd64 release...
	if [[ "${arch}" == "x32" ]]; then
		arch="amd64"
	fi

	respond "releases/${arch}/autobuilds"

	return 0
} # getautobulidpath

function getsnapshotpath() {
	local arch variant
	eval $( std::parseargs -- "${@}" ) || {
		set -- $( std::parseargs --strip -- "${@}" )
		arch="${1:-}" ; shift
		variant="${1:-}" ; shift
	}

	[[ -n "${arch:-}" ]] || \
		die "${FUNCNAME}: Required parameter '-arch' missing"

	local autobuildpath="$( getautobuildpath -arch "${arch}" )"

	[[ -n "${autobuildpath:-}" ]] || \
		die "${FUNCNAME}: Invalid '\$autobuildpath' received"

	respond "${autobuildpath}/current-stage3-${arch}${variant:+-}${variant:-}"

	return 0
} # getsnapshotpath

function fetchversion() {
	local mirror arch variant
	eval $( std::parseargs -- "${@}" ) || {
		set -- $( std::parseargs --strip -- "${@}" )
		mirror="${1:-}" ; shift
		arch="${1:-}" ; shift
		variant="${1:-}" ; shift
	}

	[[ -n "${arch:-}" ]] || \
		die "${FUNCNAME}: Required parameter '-arch' missing"

	local autobuildpath="$( getautobuildpath -arch "${arch}" )"

	[[ -n "${autobuildpath:-}" ]] || \
		die "${FUNCNAME}: Invalid '\$autobuildpath' received"

	local url="${autobuildpath}/latest-stage3-${arch}${variant:+-}${variant:-}.txt"

	respond "$( downloadtext -mirror "${mirror:-}" -url "${url}" -stripcomments 1 -filter "sed 's:/.*$::'" )"

	return 0
} # fetchversion

function getstage3() {
	local mirror arch snapshot destination variant
	local -i rc=0
	eval $( std::parseargs -- "${@}" ) || {
		set -- $( std::parseargs --strip -- "${@}" )
		mirror="${1:-}" ; shift
		arch="${1:-}" ; shift
		snapshot="${1:-}" ; shift
		destination="${1:-}" ; shift
		variant="${1:-}" ; shift
	}

	[[ -n "${arch:-}" ]] || \
		die "${FUNCNAME}: Required parameter '-arch' missing"
	[[ -n "${destination:-}" ]] || \
		{ (( action )) && die "${FUNCNAME}: Required parameter '-destination' missing" ; }
	[[ -d "${destination:-}" ]] || \
		{ (( action )) && die "${FUNCNAME}: Directory '${destination}' specified by parameter '-destination' does not exist" ; }

	local snapshotpath="$( getsnapshotpath -arch "${arch}" -variant "${variant:-}" )"

	[[ -n "${snapshot:-}" ]] || \
		die "${FUNCNAME}: Invalid '\$snapshot' received"

	local stage3="stage3-${arch}${variant:+-}${variant:-}-${snapshot}.tar.bz2"
	local digest="${destination:-}/${stage3}.DIGESTS.asc"

	# Download DIGEST file
	info "Downloading ASCII digests ..." >&2
	if (( action )); then
		downloadtext -mirror "${mirror:-}" -url "${snapshotpath}/${stage3}.DIGESTS.asc" > "${digest}"
		if ! [[ -s "${digest}" ]]; then
			[[ -e "${digest}" ]] && rm "${digest}"
			error "Unable to download checksum file" >&2
			return 1
		fi
	fi

	# Check PGP signature of checksum file
	#

	# Create working directory...
	info "Creating PGP temporary working directory ..." >&2
	if (( action )); then
		local pgptmp="$( mktemp --tmpdir --directory "${NAME}.pgp.XXXXXXXX" )"
		rc=${?}
		if ! [[ -d "${pgptmp:-}" && -w "${pgptmp}" ]]; then
			error "Unable to create temporary directory: ${rc}" >&2
			[[ -d "${pgptmp:-}" ]] && rmdir "${pgptmp}"
			rm "${digest}"
			return 1
		fi
	fi

	# ... then import Gentoo Linux Release Engineering Automated Weekly
	# Release Key ...
	info "Importing PGP public key with fingerprint '${PGPPUBKEYFINGERPRINT}' ..." >&2
	if (( action )); then
		if ! gpg >&2 \
			--quiet \
			--homedir "${pgptmp}" \
			--keyserver "${PGPKEYSERVER}" \
			--recv-keys "${PGPPUBKEYFINGERPRINT}"
		then
			rc=${?}
			error "gpg: Failed to import public key from keyserver '${PGPKEYSERVER}': ${rc}" >&2
			rm "${digest}"
			rm -r "${pgptmp}"
			return 1
		fi

		# ... and set owner-trust for this key ...
		if ! echo "${PGPPUBKEYFINGERPRINT}:6:" | \
			gpg >&2 \
				--quiet \
				--homedir "${pgptmp}" \
				--import-ownertrust
		then
			error "gpg: Failed to set ownertrust for key '${PGPPUBKEYFINGERPRINT}:6:'" >&2
			rm "${digest}"
			rm -r "${pgptemp}"
			return 1
		fi
	fi

	info "Checking PGP signature of digests ..." >&2
	if (( action )); then
		# ... then verify the signature ...
		if ! gpg >&2 \
			--quiet \
			--homedir "${pgptmp}" \
			--verify "${digest}"
		then
			rc=${?}
			error "gpg: Signature verification of checksum file '${digest}' failed: ${rc}" >&2
			rm "${digest}"
			rm -r "${pgptmp}"
			return 1
		fi

		rm -r "${pgptmp}"
	fi

	info "Extracting SHA512 and WHIRLPOOL checksums from PGP-verified digests ..." >&2
	if (( action )); then
		# Consider only the signed part of the .asc file ...
		local checkedfile="${destination}/${stage3}.DIGESTS.checked"
		awk -- 'START { doprint=0 } ; /^-----BEGIN PGP SIGNED MESSAGE/ { doprint=1 } ; /^-----BEGIN PGP SIGNATURE/ { doprint=0 } ; ( doprint ) { print $0 }' "${digest}" > "${checkedfile}"

		rm "${digest}"

		# ... and extract the SHA512 and WHIRLPOOL sums ...
		local sha512sum1="$( \
			  grep -A 1 'SHA512' "${checkedfile}" \
			| grep -v '.CONTENTS$' \
			| grep '^[a-z0-9]' \
			| awk '{ print $1 }'
		)"
		local whirlpoolsum1="$( \
			  grep -A 1 'WHIRLPOOL' "${checkedfile}" \
			| grep -v '.CONTENTS$' \
			| grep '^[a-z0-9]' \
			| awk '{ print $1 }'
		)"
		debug "Upstream sha512 => ${sha512sum1}" >&2
		debug "Upstream whirlpool => ${whirlpoolsum1}" >&2

		rm "${checkedfile}"

		if ! (( 128 == ${#sha512sum1}  & 128 == ${#whirlpoolsum1} )); then
			error "Unable to parse digest file" >&2
			return 1
		fi
	fi

	# Finally, download stage3 tarball ...
	info "Fetching '${stage3}' ..." >&2
	if (( action )); then
		download -mirror "${mirror:-}" -url "${snapshotpath}/${stage3}" -destination "${destination}/${stage3}"
	fi

	info "Verifying downloaded stage3 file ..." >&2
	if (( action )); then
		# Verify checksums ...
		info "Verifying digests ..." >&2
		local -i checksumresult=0
		local sha512sum2="$(
			  openssl dgst -r -sha512 "${destination}/${stage3}" \
			| awk '{ print $1 }'
		)"
		debug "Downloaded sha512 => ${sha512sum2}" >&2
		if [[ "${sha512sum1}" == "${sha512sum2}" ]]; then
			info "sha512 checksum matches" >&2
		else
			error "sha512 checksum does not match" >&2
			(( checksumresult ++ ))
		fi

		local whirlpoolsum2="$(
			  openssl dgst -r -whirlpool "${destination}/${stage3}" \
			| awk '{ print $1 }'
		)"
		debug "Downloaded whirlpool => ${whirlpoolsum2}" >&2
		if [[ "${whirlpoolsum1}" == "$whirlpoolsum2" ]]; then
			info "WHIRLPOOL checksum matches" >&2
		else
			error "WHIRLPOOL checksum does not match" >&2
			(( checksumresult ++ ))
		fi

		if (( checksumresult )); then
			error "${checksumresult} checksums failed to match" >&2
			rm "${destination}/${stage3}"
			return 1
		fi
	fi

	respond "${stage3}"

	return 0
} # getstage3

function main() {
	local variant
	local arch="${ARCH:-amd64}"
	local mirror="${MIRROR:-https://distfiles.gentoo.org}"
	#local mirror="${MIRROR:-http://mirror.ovh.net/gentoo-distfiles}"
	local -i rc=0

	while [[ -n "${1:-}" ]]; do
		case "${1:-}" in
			--ignore)
				ignore=1
				;;
			--pretend|--dry-run)
				action=0
				;;
			nomultilib|hardened|hardened+nomultilib)
				variant="${1}"
				;;
			amd64|x32)
				arch="${1}"
				;;
			http*)
				mirror="${1}"
				;;
			*)
				std::usage
				;;
		esac
		shift
	done
	if [[ "${arch:-}" == "x32" && -n "${variant:-}" ]]; then
		die "Archtecture '${arch}' has no variant '${variant}'"
	fi

	tag="gentoo-${arch}${variant:+-}${variant:-}"

	version=$( fetchversion -mirror "${mirror}" -arch "${arch}" -variant "${variant:-}" )
	if ! [[ -n "${version:-}" ]]; then
		die "Cannot determine latest build version of '${tag}'"
	fi

	tag=$( echo "${tag}" | sed "s/\+/-/" )
	vertag="${tag}:${version}"

	# Check for existing docker images tagged with current build version
	local _repo extag _id _etc
	local -i dup=0
	while read _repo extag _id _etc; do
		if [[ "${extag}" == "${version}" ]]; then
			warn "docker already has a(n) '${NAMESPACE}/${vertag}' image"
			dup=1
		fi
	done < <( docker images "${NAMESPACE}/${tag}" )
	(( dup & !( ignore ) )) && die "Please remove duplicate images prior to rebuilding this image"

	if ! (( action )); then
		warn "Dry-run mode - not downloading data or calculating digests"
	fi

	if (( action )); then
		destination="$( mktemp --tmpdir --directory "${NAME}.XXXXXXXX" )"
		rc=${?}
		if ! [[ -d "${destination:-}" && -w "${destination}" ]]; then
			error "Unable to create temporary directory: ${rc}"
			[[ -d "${destination:-}" ]] && rmdir "${destination}"
			return 1
		fi
	fi

	stage3=$( getstage3 -mirror "${mirror}" -arch "${arch}" -snapshot "${version}" -destination "${destination:-}" -variant "${variant:-}" )
	rc=${?}
	if (( action )); then
		if (( rc )) || ! [[ -n "${stage3:-}" && -e "${destination}/${stage3}" ]]; then
			error "Download of '${stage3}' to '${destination}' failed: ${rc}"
			rmdir "${destination}"
			return 1
		fi
	fi

	info "Importing '${stage3}' into docker ..."
	if (( action )); then
		dockerimage=$( bzip2 -9cd "${destination}/${stage3}" | docker import - "${vertag}" )

		rm "${destination}/${stage3}"
		rmdir "${destination}"

		docker tag "${dockerimage}" "${NAMESPACE}/${vertag}" || return ${?}
		docker tag "${dockerimage}" "${NAMESPACE}/${tag}:latest" || return ${?}

		# docker push $NAMESPACE/$vertag
	fi

	info "Image '${NAMESPACE}/${vertag}' successfully imported"

	return 0
} # main

declare std_USAGE="[--dry-run] [--ignore] [amd64|x32] [nomultilib|hardened|hardened+nomultilib] [mirror-url]"

(( std_TRACE )) && set -o xtrace

main "${@:-}"

(( std_TRACE )) && set +o xtrace

exit ${?}

# vi: set syntax=sh:
