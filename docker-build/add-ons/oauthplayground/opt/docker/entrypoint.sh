#!/bin/bash

if [ -z "$HOSTNAME" ]
then
  HOSTNAME=playground.webinar.local
fi

# setting the SSL port to 8448 if none was given
#
if [ -z "$SSL_PORT" ]
then
  printf "using default SSL port 8448\n"
  SSL_PORT=8448
fi

# replace @@variable@@ in server.xml with the real values
#
sed -i "s/@@hostname@@"/${HOSTNAME}/g /usr/local/tomcat/conf/server.xml
sed -i "s/@@sslport@@"/${SSL_PORT}/g /usr/local/tomcat/conf/server.xml
sed -i "s/@@sslpwd@@"/${SSL_PWD}/g /usr/local/tomcat/conf/server.xml

# overwrite the variables since they are not needed anywhere anymore
#
unset HOSTNAME=
unset SSL_PORT=
unset SSL_PWD=

# run the original tomcat entry point command as specified in tomcat's Dockerfile
#
sh /usr/local/tomcat/bin/catalina.sh run