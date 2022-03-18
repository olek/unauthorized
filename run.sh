#!/usr/bin/env bash

mvn package && java \
  -Dorg.apache.commons.logging.Log=org.apache.commons.logging.impl.SimpleLog \
  -Dorg.apache.commons.logging.simplelog.showdatetime=true \
  -Dorg.apache.commons.logging.simplelog.log.org.apache.http=WARN \
  -Dorg.apache.commons.logging.simplelog.log.org.apache.http.wire=WARN \
  -jar target/unauthorized-0.1.0.jar
