FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server git \
 && mkdir -p /run/sshd \
 && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
