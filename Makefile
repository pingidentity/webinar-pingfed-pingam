# Build referenced docker images
# - these two images have to exit before running `build_all`
#
build_prereq: build_docker_openjdk_17 build_tomcat

# Compile java and build all images
#
build_all: build_java build_docker_pf build_docker_am build_docker_pd build_docker_ds

# Compile java and build all images using the builder image
#
build_all_builder: build_java_builder build_docker_pf build_docker_am build_docker_pd build_docker_ds

build_java:
	mvn clean package

build_docker_pf:
	docker build --no-cache --tag webinar/pf:latest --build-arg version=pingfederate-12.3.3.zip --no-cache  -f Dockerfile_pf .

build_docker_am:
	docker build --no-cache --tag webinar/openam:latest --build-arg version=AM-8.0.1.war -f Dockerfile_am .

build_docker_pd:
	docker build --no-cache  --tag webinar/pd:latest --build-arg version=PingDirectory-10.3.0.0.zip --build-arg hostname=$(shell cat .env | grep HOSTNAME_PD) -f Dockerfile_pd .

build_docker_ds:
	docker build --no-cache --tag webinar/ds:latest \
	--build-arg version=DS-8.0.0.zip \
	--build-arg deploymentid=$(shell cat .env | grep DEPLOYMENT_ID | sed -e "s/DEPLOYMENT_ID=//g") \
	--build-arg deploymentpwd=$(shell cat .env | grep DEPLOYMENT_PASSWORD | sed -e "s/DEPLOYMENT_PASSWORD=//g") \
	--build-arg hostname=$(shell cat .env | grep HOSTNAME_DS | sed -e "s/HOSTNAME_DS=//g") \
	--build-arg sslpwd=$(shell cat .env | grep SSL_PWD | sed -e "s/SSL_PWD=//g") \
	--build-arg truststorepwd=changeit \
	-f Dockerfile_ds .

# Creates a docker image that contains Java and Maven and compiles the code
# This is useful if you do not want to fiddle around with Maven
# Run this target before running 'build_all_builder'
#
build_builder:
	docker build --no-cache --tag webinar/builder:latest -f Dockerfile_builder .

# Compile the code using the builder image
# Use this target if you do not have Maven installed
# Run the target 'build_builder' once before running this target
#
build_java_builder:
	docker run -v `pwd`:/tmp webinar/builder:latest mvn -f "/tmp/pom.xml" clean package

# Building an image for OAuth Playground
# - see docker-build/add-ons/oauthplayground/README.md before running it
#
build_docker_playground:
	docker build --no-cache --tag webinar/oauth-playground:latest --no-cache  -f Dockerfile_playground .

# Helper to generate below that are used in .env:
# - DEPLOYMENT_PASSWORD=QNt8...JEuU
# - DEPLOYMENT_ID=Aftg...7bg
#
build_docker_pingds_helper:
	docker build --no-cache --tag webinar/ds-helper:latest --build-arg version=DS-8.0.0.zip -f Dockerfile_ds_helper .

# Base for images that use java 17
#
build_docker_openjdk_17:
	docker build --no-cache  --tag webinar/openjdk:17 -f Dockerfile_openjdk17 .

# Base tomcat image for PingAM
#
build_tomcat:
	docker build --no-cache  --tag webinar/tomcat:10 -f Dockerfile_tomcat .

# Once all images are up and running, the products can be configured with this task
#
configure_setup:
	docker exec -it pdwebinarlocal sh -c "/opt/docker/import_ldifs.sh"
	java -jar target/setup-1.0.jar configure_pingfederate configure_pingam

# Once PingAM  (openam) is up and running, this task imports example journeys
#
import_journeys:
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
	# AWS SNS journey (Push)**: for this to work PingAM needs to be accessible via the internet
	# name = WebinarJourneySNS
	frodo journey import -k -f docker-build/add-ons/openam/journeys/WebinarJourneySNS.journey.json /openam $(shell cat .env | grep PINGAM_REALM | cut -d= -f2-)
	#
	# WebAuthN journey
	# name = WebinarJourneyWebAuthN
	frodo journey import -k -f docker-build/add-ons/openam/journeys/WebinarJourneyWebAuthN.journey.json /openam $(shell cat .env | grep PINGAM_REALM | cut -d= -f2-)
	#
	# Leveraging back channel authentication. This allows forwarding values from PingFederate to PingAM
	# name = WebinarJourneyBackChannelAuth
	frodo journey import -k -f docker-build/add-ons/openam/journeys/WebinarJourneyBackChannelAuth.journey.json /openam $(shell cat .env | grep PINGAM_REALM | cut -d= -f2-)
	#
	# The journey WebinarJourney uses the script node WebinarSetSessionProps
	# It needs to be updated in order to retrieve user attributes that are specified in '.env#PINGAM_LDAP_ATTRIBUTE'
	#
	java -jar target/setup-1.0.jar update_script_node

# Remove all files that were generated
# Do not run this unless you are sure a missing file will not cause issues
# Other than that, starting from scratch is required
#
clean_all:
	rm -fr .env
	rm -fr dev/*.p12
	rm -fr dev/*.bak
	rm -fr dev/*.crt