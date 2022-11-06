FROM alpine:3.16.2 as builder

RUN apk add --update wget zip openjdk8 git

RUN wget --output-document=/tmp/maven.zip https://dlcdn.apache.org/maven/maven-3/3.8.6/binaries/apache-maven-3.8.6-bin.zip \
  && unzip /tmp/maven.zip -d /tmp/ \
  && mkdir -p /usr/local/maven/ \
  && mv /tmp/apache-maven-3.8.6/* /usr/local/maven/ \
  && rm -Rf /tmp/apache-maven-3.8.6/

RUN cd /tmp \
  && git clone https://github.com/claudineyns/icap-server \
  && /usr/local/maven/bin/mvn -q -f icap-server/pom.xml package \
  && mv icap-server/target/*-shaded.jar /tmp/runner.jar

FROM alpine:3.16.2

RUN mkdir /app

COPY --from=builder /tmp/runner.jar /app/runner.jar

RUN apk add --update clamav clamav-daemon openjdk8-jre-base

RUN echo '#!/bin/sh' >> /app/startup.sh \
  && echo 'freshclam' >> /app/startup.sh \
  && echo '/usr/bin/java -jar /app/runner.jar' >> /app/startup.sh \
  && chmod +x /app/startup.sh

ENTRYPOINT ["/app/startup.sh"]
