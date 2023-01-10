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
 && echo 'Building application...' \
 && /usr/local/maven/bin/mvn -f icap-server/pom.xml package \
 && mv icap-server/target/*-shaded.jar /tmp/runner.jar \
 && echo 'Build completed.'

FROM alpine:3.16.2

ENV TZ=BRT+3

MAINTAINER Claudiney Nascimento <contato@claudiney.dev>

LABEL description="ICAP Server for virus scan implemented in Java Language, which uses linux clamav or windows defender" \
      io.k8s.description="ICAP Server for virus scan implemented in Java Language, which uses linux clamav or windows defender" \
      io.k8s.display-name="ICAP Server Java (1.0)" \
      io.openshift.expose-services="1344;icap" \
      io.openshift.tags="icap,java" \
      maintainer="Claudiney Nascimento <contato@claudiney.dev>" \
      name="claudiney/icap-server-java" \
      summary="ICAP Server for virus scan" \
      source.url="https://github.com/claudineyns/icap-server.git" \
      url="docker.io/claudiney/icap-server-java:latest" \
      version="latest"

RUN mkdir -pv /app/run

COPY --from=builder /tmp/runner.jar /app/run/app.jar

RUN addgroup -g 1001 -S clamav \
 && adduser -S -G root -D -H -u 1001 clamav \
 && addgroup clamav clamav

RUN apk add --update clamav clamav-daemon openjdk8-jre-base

RUN echo '#!/bin/sh' >> /app/run/startup.sh \
 && echo 'freshclam' >> /app/run/startup.sh \
 && echo '/usr/bin/java -jar /app/run/app.jar' >> /app/run/startup.sh \
 && chmod +x /app/run/startup.sh

RUN chown -R 1001 /app \
 && chgrp -R 0 /app

USER 1001

EXPOSE 1344

CMD /app/run/startup.sh
