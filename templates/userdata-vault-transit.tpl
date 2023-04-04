#!/usr/bin/env bash
set -x
exec > >(tee /var/log/tf-user-data.log|logger -t user-data ) 2>&1

logger() {
  DT=$(date '+%Y/%m/%d %H:%M:%S')
  echo "$DT $0: $1"
}

logger "Running"

##--------------------------------------------------------------------
## Variables

# Get Private IP address
PRIVATE_IP=$(curl http://169.254.169.254/latest/meta-data/local-ipv4)
PUBLIC_IP=$(curl http://169.254.169.254/latest/meta-data/public-ipv4)

VAULT_ZIP="${tpl_vault_zip_file}"

# Detect package management system.
YUM=$(which yum 2>/dev/null)
APT_GET=$(which apt-get 2>/dev/null)

##--------------------------------------------------------------------
## Functions

user_rhel() {
  # RHEL/CentOS user setup
  sudo /usr/sbin/groupadd --force --system $${USER_GROUP}

  if ! getent passwd $${USER_NAME} >/dev/null ; then
    sudo /usr/sbin/adduser \
      --system \
      --gid $${USER_GROUP} \
      --home $${USER_HOME} \
      --no-create-home \
      --comment "$${USER_COMMENT}" \
      --shell /bin/false \
      $${USER_NAME}  >/dev/null
  fi
}

user_ubuntu() {
  # UBUNTU user setup
  if ! getent group $${USER_GROUP} >/dev/null
  then
    sudo addgroup --system $${USER_GROUP} >/dev/null
  fi

  if ! getent passwd $${USER_NAME} >/dev/null
  then
    sudo adduser \
      --system \
      --disabled-login \
      --ingroup $${USER_GROUP} \
      --home $${USER_HOME} \
      --no-create-home \
      --gecos "$${USER_COMMENT}" \
      --shell /bin/false \
      $${USER_NAME}  >/dev/null
  fi
}

##--------------------------------------------------------------------
## Install Base Prerequisites

logger "Setting timezone to UTC"
sudo timedatectl set-timezone UTC
sudo systemctl disable ufw

if [[ ! -z $${YUM} ]]; then
  logger "RHEL/CentOS system detected"
  logger "Performing updates and installing prerequisites"
  sudo yum-config-manager --enable rhui-REGION-rhel-server-releases-optional
  sudo yum-config-manager --enable rhui-REGION-rhel-server-supplementary
  sudo yum-config-manager --enable rhui-REGION-rhel-server-extras
  sudo yum -y check-update
  sudo yum install -q -y wget unzip bind-utils ruby rubygems ntp jq
  sudo systemctl start ntpd.service
  sudo systemctl enable ntpd.service
elif [[ ! -z $${APT_GET} ]]; then
  logger "Debian/Ubuntu system detected"
  logger "Performing updates and installing prerequisites"
  sudo apt-get -qq -y update
  sudo apt-get install -qq -y wget unzip dnsutils ruby rubygems ntp jq
  sudo systemctl start ntp.service
  sudo systemctl enable ntp.service
  logger "Disable reverse dns lookup in SSH"
  sudo sh -c 'echo "\nUseDNS no" >> /etc/ssh/sshd_config'
  sudo service ssh restart
else
  logger "Prerequisites not installed due to OS detection failure"
  exit 1;
fi

##--------------------------------------------------------------------
## Install AWS-Specific Prerequisites

if [[ ! -z $${YUM} ]]; then
  logger "RHEL/CentOS system detected"
  logger "Performing updates and installing prerequisites"
  curl --silent -O https://bootstrap.pypa.io/get-pip.py
  sudo python get-pip.py
  sudo pip install awscli
elif [[ ! -z $${APT_GET} ]]; then
  logger "Debian/Ubuntu system detected"
  logger "Performing updates and installing prerequisites"
  sudo apt-get -qq -y update
  sudo apt-get install -qq -y awscli
else
  logger "AWS Prerequisites not installed due to OS detection failure"
  exit 1;
fi


##--------------------------------------------------------------------
## Configure Vault user

USER_NAME="vault"
USER_COMMENT="HashiCorp Vault user"
USER_GROUP="vault"
USER_HOME="/srv/vault"

if [[ ! -z $${YUM} ]]; then
  logger "Setting up user $${USER_NAME} for RHEL/CentOS"
  user_rhel
elif [[ ! -z $${APT_GET} ]]; then
  logger "Setting up user $${USER_NAME} for Debian/Ubuntu"
  user_ubuntu
else
  logger "$${USER_NAME} user not created due to OS detection failure"
  exit 1;
fi

##--------------------------------------------------------------------
## Install Vault

logger "Downloading pkcs11"
cd /tmp
sudo apt install opensc -y
curl -o /tmp/vault-pkcs11-provider_0.2.0_linux-el8_amd64.zip https://releases.hashicorp.com/vault-pkcs11-provider/0.2.0/vault-pkcs11-provider_0.2.0_linux-el8_amd64.zip
unzip /tmp/vault-pkcs11-provider_0.2.0_linux-el8_amd64.zip

logger "Downloading Vault"
curl -o /tmp/vault.zip $${VAULT_ZIP}

sleep 10

logger "Installing Vault"
sudo unzip -o /tmp/vault.zip -d /usr/local/bin/
sudo chmod 0755 /usr/local/bin/vault
sudo chown vault:vault /usr/local/bin/vault
sudo mkdir -pm 0755 /etc/vault.d
sudo mkdir -pm 0755 /etc/ssl/vault

logger "/usr/local/bin/vault --version: $(/usr/local/bin/vault --version)"

logger "Configuring Vault"

sudo mkdir -pm 0755 ${tpl_vault_storage_path}
sudo chown -R vault:vault ${tpl_vault_storage_path}
sudo chmod -R a+rwx ${tpl_vault_storage_path}

echo "${tpl_vault_lic}" >> /etc/vault.d/license.hclic

sudo tee /etc/vault.d/vault.hcl <<EOF
storage "raft" {
  path    = "/vault/vault_1"
  node_id = "vault_1"
}


listener "tcp" {
  address     = "0.0.0.0:8200"
  cluster_address     = "0.0.0.0:8201"
  tls_disable = true
}

api_addr = "http://$${PUBLIC_IP}:8200"
cluster_addr = "http://$${PRIVATE_IP}:8201"
disable_mlock = true
ui=true
license_path = "/etc/vault.d/license.hclic"
EOF

sudo chown -R vault:vault /etc/vault.d /etc/ssl/vault
sudo chmod -R 0644 /etc/vault.d/*

sudo tee -a /etc/environment <<EOF
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_SKIP_VERIFY=true
EOF

source /etc/environment

logger "Granting mlock syscall to vault binary"
sudo setcap cap_ipc_lock=+ep /usr/local/bin/vault

##--------------------------------------------------------------------
## Install Vault Systemd Service

read -d '' VAULT_SERVICE <<EOF
[Unit]
Description=Vault
Requires=network-online.target
After=network-online.target

[Service]
Restart=on-failure
PermissionsStartOnly=true
ExecStartPre=/sbin/setcap 'cap_ipc_lock=+ep' /usr/local/bin/vault
ExecStart=/usr/local/bin/vault server -config /etc/vault.d
ExecReload=/bin/kill -HUP \$MAINPID
KillSignal=SIGTERM
User=vault
Group=vault

[Install]
WantedBy=multi-user.target
EOF

##--------------------------------------------------------------------
## Install Vault Systemd Service that allows additional params/args

sudo tee /etc/systemd/system/vault@.service > /dev/null <<EOF
[Unit]
Description=Vault
Requires=network-online.target
After=network-online.target

[Service]
Environment="OPTIONS=%i"
Restart=on-failure
PermissionsStartOnly=true
ExecStartPre=/sbin/setcap 'cap_ipc_lock=+ep' /usr/local/bin/vault
ExecStart=/usr/local/bin/vault server -config /etc/vault.d \$OPTIONS
ExecReload=/bin/kill -HUP \$MAINPID
KillSignal=SIGTERM
User=vault
Group=vault

[Install]
WantedBy=multi-user.target
EOF

if [[ ! -z $${YUM} ]]; then
  SYSTEMD_DIR="/etc/systemd/system"
  logger "Installing systemd services for RHEL/CentOS"
  echo "$${VAULT_SERVICE}" | sudo tee $${SYSTEMD_DIR}/vault.service
  sudo chmod 0664 $${SYSTEMD_DIR}/vault*
elif [[ ! -z $${APT_GET} ]]; then
  SYSTEMD_DIR="/lib/systemd/system"
  logger "Installing systemd services for Debian/Ubuntu"
  echo "$${VAULT_SERVICE}" | sudo tee $${SYSTEMD_DIR}/vault.service
  sudo chmod 0664 $${SYSTEMD_DIR}/vault*
else
  logger "Service not installed due to OS detection failure"
  exit 1;
fi

sudo systemctl enable vault
sudo systemctl start vault

#=================================

sleep 2

sudo tee /etc/profile.d/vault.sh > /dev/null <<"EOF"
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_SKIP_VERIFY=true
EOF
source /etc/profile.d/vault.sh


# Initialise Vault
logger "Initialise Vault"
echo "\n\033[32m---Configuring Vault for ---\033[0m"
init_output=$(vault operator init -key-shares=1 -key-threshold=1 -format=json)
echo $init_output
# Store the root token and unseal keys in variables
export VAULT_TOKEN=$(echo "$${init_output}" | jq -r ".root_token")
export unseal_key=$(echo "$${init_output}" | jq -r ".unseal_keys_b64[]")
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_SKIP_VERIFY=true

# Unseal leader
vault operator unseal $(eval echo $${unseal_key})

echo $unseal_key >> /tmp/unseal_key.txt

echo $VAULT_TOKEN | vault login -
#vault login $VAULT_TOKEN
vault secrets enable transit
vault write -f transit/keys/unseal_key

sudo tee /etc/vault.d/autounseal.hcl <<EOF
path "transit/encrypt/unseal_key" {
   capabilities = [ "update" ]
}

path "transit/decrypt/unseal_key" {
   capabilities = [ "update" ]
}

path "kmip/*" {
  capabilities = [ "create", "read", "update", "delete", "list" ]
}
EOF



cd /etc/vault.d/
vault secrets enable kmip
vault write kmip/config listen_addrs=0.0.0.0:5696 server_ips=10.0.101.21,10.0.101.31,127.0.0.1
vault write -f kmip/scope/my-service
vault write kmip/scope/my-service/role/admin operation_all=true
vault write -f -format=json kmip/scope/my-service/role/admin/credential/generate | tee /etc/vault.d/kmip.json
jq --raw-output --exit-status '.data.ca_chain[]' /etc/vault.d/kmip.json > /etc/vault.d/ca.pem
jq --raw-output --exit-status '.data.certificate' /etc/vault.d/kmip.json > /etc/vault.d/cert.pem

sudo tee /etc/vault-pkcs11.hcl <<EOF
slot {
    server = "127.0.0.1:5696"
    tls_cert_path = "/etc/vault.d/cert.pem"
    ca_path = "/etc/vault.d/ca.pem"
    scope = "my-service"
}
EOF

logger "autounseal policy"
vault policy write autounseal /etc/vault.d/autounseal.hcl

logger "create wrap token"

vault token create -orphan -policy="autounseal" -wrap-ttl=20m -period=24h

logger "Complete"




