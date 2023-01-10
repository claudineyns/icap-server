FROM alpine:3.16.2 as builder

ARG MAVEN_VERSION=3.8.7

RUN apk add --update wget zip openjdk8 git

RUN wget -q -O /tmp/maven.zip https://dlcdn.apache.org/maven/maven-3/3.8.7/binaries/apache-maven-${MAVEN_VERSION}-bin.zip \
 && unzip /tmp/maven.zip -d /tmp/ \
 && mkdir -p /usr/local/maven/ \
 && mv /tmp/apache-maven-${MAVEN_VERSION}/* /usr/local/maven/ \
 && rm -Rf /tmp/apache-maven-${MAVEN_VERSION}/

RUN cd /tmp \
 && git clone https://github.com/claudineyns/icap-server.git \
 && /usr/local/maven/bin/mvn -q -f icap-server/pom.xml package \
 && mv icap-server/target/*-shaded.jar /tmp/runner.jar

FROM alpine:3.16.2

LABEL description="ICAP Server for virus scan implemented in Java Language, which uses linux clamav or windows defender" \
      io.k8s.description="ICAP Server for virus scan implemented in Java Language, which uses linux clamav or windows defender" \
      io.k8s.display-name="ICAP Server Java (1.0)" \
      io.openshift.expose-services="1344;icap" \
      io.openshift.tags="icap,java" \
      maintainer="Claudiney Nascimento <contato@claudiney.dev>" \
      name="claudiney/icap-server-java" \
      summary="ICAP Server for virus scan" \
      source.url="https://github.com/claudineyns/icap-server" \
      url="docker.io/claudiney/icap-server-java:latest" \
      version="latest"

RUN mkdir /app

COPY --from=builder /tmp/runner.jar /app/runner.jar

RUN apk add --update clamav clamav-daemon openjdk8-jre-base

VOLUME /var/lib/clamav

RUN echo '#!/bin/sh' >> /app/startup.sh \
 && echo 'freshclam' >> /app/startup.sh \
 && echo '/usr/bin/java -jar /app/runner.jar' >> /app/startup.sh \
 && chmod +x /app/startup.sh

RUN chown -R 1001 /app \
 && chgrp -R 0 /app

USER 1001

EXPOSE 1344

CMD /app/startup.sh
