FROM debian:trixie-slim

ARG GIT_STRONGSWAN_URL=https://github.com/robo-w/strongswan-epdg.git
ARG GIT_STRONGSWAN_BRANCH=robo/epdg-client

ARG GIT_PYSIM_URL=https://gitea.osmocom.org/sim-card/pysim.git

ENV DEBIAN_FRONTEND=noninteractive

# Install Osmocom variant of strongSwan
RUN apt-get update && \
  apt-get install -y libosmocore libgmp10 gperf python3 libpcsclite1 \
    git autoconf automake libtool pkg-config m4 libosmocore-dev libgmp-dev bison flex make gettext libpcsclite-dev \
    libssl-dev && \
  cd && \
  git clone --depth 1 -b ${GIT_STRONGSWAN_BRANCH} ${GIT_STRONGSWAN_URL} strongswan-epdg && \
  cd strongswan-epdg && \
  autoreconf -i && \
  ./configure --enable-eap-sim-pcsc --enable-p-cscf --enable-save-keys --enable-eap-sim --enable-eap-aka --enable-openssl && \
  make && \
  make install && \
  ldconfig && \
  cd && \
  rm -rf strongswan-epdg && \
  apt-get purge -y git autoconf automake libtool pkg-config m4 libosmocore-dev libgmp-dev bison flex make gettext libpcsclite-dev && \
  apt-get autoremove -y && \
  apt-get clean

# Install pySim with required dependencies
RUN apt-get update && \
  apt-get install -y git pcscd python3-setuptools python3-pip python3-pycryptodome python3-pyscard python3-venv libpcsclite-dev && \
  apt-get clean && \
  python3 -m venv /root/.venv/pysim && \
  cd && \
  git clone --depth 1 ${GIT_PYSIM_URL} pysim && \
  /root/.venv/pysim/bin/pip install -r pysim/requirements.txt

# Install packages required for strongSwan setup, operation and manual testing
RUN apt-get update && \
  apt-get install -y net-tools dnsutils iproute2 telnet iputils-ping tcpdump nano jq && \
  apt-get clean

VOLUME /root/epdg-logs

RUN echo "alias ims-netns='ip netns exec ims'" >> /root/.bashrc

COPY --chown=root:root --chmod=0644 strongswan-config/charon-logging.conf /usr/local/etc/strongswan.d/charon-logging.conf
COPY --chown=root:root --chmod=0644 strongswan-config/save-keys.conf /usr/local/etc/strongswan.d/charon/save-keys.conf
COPY --chown=root:root --chmod=0644 strongswan-config/p-cscf.conf /usr/local/etc/strongswan.d/charon/p-cscf.conf
COPY --chown=root:root --chmod=0644 strongswan-config/osmo-epdg.conf /usr/local/etc/strongswan.d/charon/osmo-epdg.conf
COPY --chown=root:root --chmod=0644 strongswan-config/charon-disable-virt-ips.conf /usr/local/etc/strongswan.d/charon-disable-virt-ips.conf
COPY --chown=root:root --chmod=0644 strongswan-config/epdg-template.conf /usr/local/etc/swanctl/conf.d/epdg.conf

COPY --chown=root:root --chmod=0755 pySim-readIMSI.py /root/pysim/pySim-readIMSI.py
COPY --chown=root:root --chmod=0755 docker-entrypoint.sh /docker-entrypoint.sh
COPY --chown=root:root --chmod=0755 ims.updown /usr/local/etc/ims.updown
COPY --chown=root:root --chmod=0755 stop-ipsec.sh /root/stop-ipsec.sh

COPY --chown=root:root ./connectivity-check /root/connectivity-check
COPY --chown=root:root ./sip-python /root/sip-python

# Copies the CA certificates to the strongSwan directory.
# If at least one CA is present there, strongSwan will send a CERTREQ in IKE_AUTH
#COPY --chown=root:root --chmod=0644 certs/*.crt /usr/local/etc/ipsec.d/cacerts/

WORKDIR /root

ENTRYPOINT ["/docker-entrypoint.sh"]
