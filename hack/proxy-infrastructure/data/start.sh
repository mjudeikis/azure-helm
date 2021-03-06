#!/bin/bash -ex

exec 2>&1

export HOME=/root
cd

yum install git -y

curl -s https://storage.googleapis.com/golang/go1.11.6.linux-amd64.tar.gz | tar -C /usr/local -xz
PATH=$PATH:/usr/local/go/bin

go get -u github.com/openshift/openshift-azure/cmd/proxy

mkdir data
cat >proxy-cert.pem <<'EOF'
{{ .Config.ServerCert | CertAsBytes | String }}
EOF

cat >proxy-key.pem <<'EOF'
{{ .Config.ServerKey | PrivateKeyAsBytes | String }}
EOF

cat >proxy-ca.pem <<'EOF'
{{ .Config.Ca | CertAsBytes | String }}
EOF

cat >/etc/systemd/system/aro-proxy.service <<'EOF'
[Unit]
Description=aro-proxy

[Service]
ExecStart=/root/go/bin/proxy -cert /root/proxy-cert.pem -key /root/proxy-key.pem -cacert /root/proxy-ca.pem -subnet "{{ .Config.NetDefinition.Vnet }}"

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload

sudo systemctl enable aro-proxy
sudo systemctl start aro-proxy

firewall-cmd --zone=public --add-port=8443/tcp --permanent
firewall-cmd --reload
