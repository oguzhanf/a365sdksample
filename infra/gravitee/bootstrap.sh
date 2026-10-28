#!/usr/bin/env bash
set -euo pipefail
umask 077
deployment_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$deployment_root"
mapfile -t runtime_layout < <(python3 - <<'PY'
import provision
settings = provision.runtime_settings(provision.read_config())
print(settings["workingDirectory"])
print(settings["dataRoot"])
print(settings["systemdService"])
PY
)
test "${#runtime_layout[@]}" -eq 3
test "$deployment_root" = "${runtime_layout[0]}"
data_root="${runtime_layout[1]}"
systemd_service="${runtime_layout[2]}"
if [ -f /etc/docker/daemon.json ]; then
    python3 - "$data_root" <<'PY'
import json, pathlib, sys
current = json.loads(pathlib.Path("/etc/docker/daemon.json").read_text()).get("data-root")
if current and current != sys.argv[1] + "/docker":
    raise SystemExit("Refusing to replace an existing Docker data root; use the recorded runtime configuration.")
PY
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg python3 python3-bcrypt unzip > "$deployment_root/package-install.log" 2>&1

# Only LUN 0 of the explicitly attached data disk may be initialized.
disk=/dev/disk/azure/scsi1/lun0
for attempt in $(seq 1 30); do
    if [ -b "$disk" ]; then break; fi
    sleep 2
done
test -b "$disk"
fstype=$(lsblk -dn -o FSTYPE "$disk")
if [ -z "$fstype" ]; then
    test "$(lsblk -nr -o NAME "$disk" | wc -l)" -eq 1
    test "$(lsblk -dn -o TYPE "$disk")" = disk
    test "$(lsblk -bdn -o SIZE "$disk")" -ge 137438953472
    mkfs.ext4 -q "$disk"
elif [ "$fstype" != ext4 ]; then
    echo "Refusing to alter an unexpected data-disk filesystem." >&2
    exit 1
fi
uuid=$(blkid -s UUID -o value "$disk")
test -n "$uuid"
mounted_target=$(findmnt -rn -S "UUID=$uuid" -o TARGET || true)
if [ -n "$mounted_target" ] && [ "$mounted_target" != "$data_root" ]; then
    echo "Refusing to move an already-mounted persistent disk; use the recorded runtime configuration." >&2
    exit 1
fi
mkdir -p "$data_root"
if ! grep -Fq "UUID=$uuid " /etc/fstab; then
    printf 'UUID=%s %s ext4 defaults,nofail 0 2\n' "$uuid" "$data_root" >> /etc/fstab
fi
if ! mountpoint -q "$data_root"; then mount "$data_root"; fi
test "$(findmnt -no UUID "$data_root")" = "$uuid"
install -d -m 0700 -o 1654 -g 1654 "$data_root/backend"

install -m 0755 -d /etc/apt/keyrings
curl --fail --silent --show-error https://download.docker.com/linux/ubuntu/gpg -o "$deployment_root/docker.asc"
gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg "$deployment_root/docker.asc"
chmod 0644 /etc/apt/keyrings/docker.gpg
. /etc/os-release
printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu %s stable\n' \
    "$(dpkg --print-architecture)" "$VERSION_CODENAME" > /etc/apt/sources.list.d/docker.list
apt-get update -qq
apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin \
    >> "$deployment_root/package-install.log" 2>&1
systemctl stop docker.service docker.socket
mkdir -p /etc/docker
python3 - "$data_root" > /etc/docker/daemon.json <<'PY'
import json, sys
print(json.dumps({"data-root": sys.argv[1] + "/docker", "log-driver": "local",
                  "log-opts": {"max-size": "10m", "max-file": "3"}}))
PY
mkdir -p /etc/systemd/system/docker.service.d
cat > /etc/systemd/system/docker.service.d/10-agentharness-data.conf <<DOCKER_UNIT
[Unit]
RequiresMountsFor=${data_root}

[Service]
ExecStartPre=/usr/bin/mountpoint -q ${data_root}
DOCKER_UNIT
printf 'vm.max_map_count=262144\n' > /etc/sysctl.d/90-agentharness-elasticsearch.conf
sysctl -p /etc/sysctl.d/90-agentharness-elasticsearch.conf > /dev/null
systemctl daemon-reload
systemctl enable --now docker.service

# APIM 4.12.0 pins the OSS request-validation policy to 1.15.1.
plugin_version=1.15.1
plugin_name="gravitee-policy-request-validation-${plugin_version}.zip"
plugin_sha256=61b5bfe74c99ab91aa36f9c1d8b45bb4c94a11856ec605af5f75f68e27485f67
plugin_url="https://download.gravitee.io/graviteeio-apim/plugins/policies/gravitee-policy-request-validation/${plugin_name}"
plugin_dir="$deployment_root/plugins"
plugin_path="${plugin_dir}/${plugin_name}"
install -d -m 0755 -o root -g root "$plugin_dir"
if [ ! -f "$plugin_path" ] || ! printf '%s  %s\n' "$plugin_sha256" "$plugin_path" | sha256sum --check --status; then
    plugin_download="${plugin_path}.download"
    rm -f "$plugin_download"
    trap 'rm -f "$plugin_download"' EXIT
    curl --proto '=https' --proto-redir '=https' --fail --location --silent --show-error \
        "$plugin_url" -o "$plugin_download"
    printf '%s  %s\n' "$plugin_sha256" "$plugin_download" | sha256sum --check --status
    chown root:root "$plugin_download"
    chmod 0444 "$plugin_download"
    mv -f "$plugin_download" "$plugin_path"
    trap - EXIT
fi
chown root:root "$plugin_path"
chmod 0444 "$plugin_path"
printf '%s  %s\n' "$plugin_sha256" "$plugin_path" > "${plugin_path}.sha256"
chmod 0444 "${plugin_path}.sha256"

# Secrets go directly from Key Vault to root-traversable-only bind-mount files.
python3 provision.py render
docker compose --file compose.runtime.json config --quiet
docker compose --file compose.runtime.json pull --ignore-buildable > "$deployment_root/image-pull.log" 2>&1
docker compose --file compose.runtime.json build internal-api > "$deployment_root/backend-build.log" 2>&1

cat > "/etc/systemd/system/$systemd_service" <<UNIT
[Unit]
Description=AgentHarness persistent Gravitee demo
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target
RequiresMountsFor=${data_root}

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${deployment_root}
ExecStartPre=/usr/bin/sha256sum --check --status ${deployment_root}/plugins/gravitee-policy-request-validation-1.15.1.zip.sha256
ExecStartPre=/usr/bin/python3 ${deployment_root}/provision.py render
ExecStart=/usr/bin/docker compose --file compose.runtime.json up --detach --remove-orphans --force-recreate
ExecStop=/usr/bin/docker compose --file compose.runtime.json stop
TimeoutStartSec=1200
TimeoutStopSec=120
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable "$systemd_service"
systemctl restart "$systemd_service"
systemctl is-active --quiet "$systemd_service"
python3 provision.py provision
echo "AgentHarness Gravitee configuration and unauthenticated-denial checks completed."
