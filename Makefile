# Compile java and build all images
#
build_all: build_java build_docker_pf build_docker_am build_docker_pd

# Compile java and build all images using the builder image
#
build_all_builder: build_java_builder build_docker_pf build_docker_am build_docker_pd

build_java:
	mvn clean package

build_docker_pf:
	docker build --no-cache --tag webinar/pf:latest --build-arg version=pingfederate-12.1.0.zip --no-cache  -f Dockerfile_pf .

build_docker_am:
	docker build --no-cache --tag webinar/openam:latest --build-arg version=AM-7.5.0.war -f Dockerfile_am .

build_docker_pd:
	docker build --no-cache  --tag webinar/pd:latest --build-arg version=PingDirectory-10.1.0.0.zip --build-arg hostname=$(shell cat .env | grep HOSTNAME_PD) -f Dockerfile_pd .

build_docker_playground:
	docker build --no-cache --tag webinar/oauth-playground:latest --no-cache  -f Dockerfile_playground .

configure_setup:
	# import LDIF fiels into PingDirectory to support MFA flows
	docker exec -it pdwebinarlocal sh -c "/opt/docker/import_ldifs.sh"
	#
	# Configure PingFederate and PingAM
	java -jar target/setup-1.0.jar

import_journeys:
	#
	# Username/Password journey
    # name = WebinarJourney
    # this is the default journey that PingFederate invokes
    # this is configured in **.env**
	frodo journey import -k -f docker-build/add-ons/openam/journeys/WebinarJourney.journey.json /openam $(shell cat .env | grep PINGAM_REALM | cut -d= -f2-)
	#
	# OATH journey (Push): this option has no dependencies to external services and is easy to execute. Nevertheless, it requires the ForgeRock Authenticator app
	# name = WebinarJourneyOAthPush
	frodo journey import -k -f docker-build/add-ons/openam/journeys/WebinarJourneyOAthPush.journey.json /openam $(shell cat .env | grep PINGAM_REALM | cut -d= -f2-)
	#
	# AWS SNS journey (Push): for this to work PingAM needs to be accessible via the internet
	# name = WebinarJourneySNS
	frodo journey import -k -f docker-build/add-ons/openam/journeys/WebinarJourneySNS.journey.json /openam $(shell cat .env | grep PINGAM_REALM | cut -d= -f2-)
	#
	# WebAuthN journey
	# name = WebinarJourneyWebAuthN
	frodo journey import -k -f docker-build/add-ons/openam/journeys/WebinarJourneyWebAuthN.journey.json /openam $(shell cat .env | grep PINGAM_REALM | cut -d= -f2-)
	#
	# The journey WebinarJourney uses the script node WebinarSetSessionProps
	# It needs to be updated in order to retrieve user attributes that are specified in '.env#PINGAM_LDAP_ATTRIBUTE'
	#
	java -jar target/setup-1.0.jar update_script_node

# Creates a docker image that contains Java and Maven and compiles the code
# This is useful if you do not want to fiddle around with Java versions and Maven
# Run this target before running 'build_all_builder'
#
build_builder:
	docker build --no-cache --tag webinar/builder:latest -f Dockerfile_builder .

# Compile the code using the builder image
# Use this target if you do not have Java and Maven installed
# Run the target 'build_builder' before running this target
#
build_java_builder:
	docker run -v `pwd`:/tmp webinar/builder:latest mvn -f "/tmp/pom.xml" clean package

# Remove all files that were generated
# Do not run this unless you are sure a missing file will not cause issues
# Other than that, starting from scratch is required
#
clean_all:
	rm -fr .env
	rm -fr dev/*.p12
	rm -fr dev/*.bak
	rm -fr dev/*.crt