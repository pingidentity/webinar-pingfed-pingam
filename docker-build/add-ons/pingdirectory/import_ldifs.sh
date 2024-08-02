#!/bin/bash

/opt/pingdirectory/bin/ldapmodify -h localhost -p 389 -D "cn=administrator" -w password -f /opt/tmp/pingamldifs/opendj_user_schema.ldif
/opt/pingdirectory/bin/ldapmodify -h localhost -p 389 -D "cn=administrator" -w password -f /opt/tmp/pingamldifs/opendj_deviceprint.ldif
/opt/pingdirectory/bin/ldapmodify -h localhost -p 389 -D "cn=administrator" -w password -f /opt/tmp/pingamldifs/opendj_dashboard.ldif
/opt/pingdirectory/bin/ldapmodify -h localhost -p 389 -D "cn=administrator" -w password -f /opt/tmp/pingamldifs/opendj_pushdevices.ldif
/opt/pingdirectory/bin/ldapmodify -h localhost -p 389 -D "cn=administrator" -w password -f /opt/tmp/pingamldifs/opendj_oathdevices.ldif
/opt/pingdirectory/bin/ldapmodify -h localhost -p 389 -D "cn=administrator" -w password -f /opt/tmp/pingamldifs/oath_2fa.ldif
/opt/pingdirectory/bin/ldapmodify -h localhost -p 389 -D "cn=administrator" -w password -f /opt/tmp/pingamldifs/opendj_deviceprofiles.ldif
/opt/pingdirectory/bin/ldapmodify -h localhost -p 389 -D "cn=administrator" -w password -f /opt/tmp/pingamldifs/opendj_webauthndevices.ldif
/opt/pingdirectory/bin/ldapmodify -h localhost -p 389 -D "cn=administrator" -w password -f /opt/tmp/pingamldifs/opendj_bounddevices.ldif
/opt/pingdirectory/bin/ldapmodify -h localhost -p 389 -D "cn=administrator" -w password -f /opt/tmp/pingamldifs/opendj_kba.ldif