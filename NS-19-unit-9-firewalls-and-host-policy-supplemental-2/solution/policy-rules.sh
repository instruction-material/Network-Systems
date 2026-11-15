#!/usr/bin/env bash
set -euo pipefail
refuse() { printf 'refusing direct or original-host UFW execution\n' >&2; exit 2; }
[[ "$(uname -s)" == "Linux" && "${EUID:-$(id -u)}" == "0" ]] || refuse
[[ -n "${COURSE_ORIGINAL_NETNS:-}" && -n "${COURSE_ORIGINAL_MNTNS:-}" && -n "${COURSE_LAB_TOKEN:-}" ]] || refuse
current_net="$(readlink /proc/self/ns/net)"
current_mount="$(readlink /proc/self/ns/mnt)"
[[ "$current_net" != "$COURSE_ORIGINAL_NETNS" && "$current_net" != "$(readlink /proc/1/ns/net)" ]] || refuse
[[ "$current_mount" != "$COURSE_ORIGINAL_MNTNS" && "$current_mount" != "$(readlink /proc/1/ns/mnt)" ]] || refuse
[[ -f /etc/ufw/.course-owned-run && "$(cat /etc/ufw/.course-owned-run)" == "$COURSE_LAB_TOKEN" ]] || refuse
[[ "${MANAGEMENT_PORT:-}" =~ ^[0-9]+$ ]] || refuse
case "${1:-}" in
  management)
    ufw allow "${MANAGEMENT_PORT}/tcp"
    ;;
  web)
    ufw allow "Course Web"
    ;;
  *) refuse ;;
esac
