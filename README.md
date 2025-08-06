# Orchestration with PingFederate, PingAM, PingDirectory and PingDS

This project is an example setup that takes advantage of the orchestration features that PingAM provides.

The target audiences for this setup are administrators and developers who want to understand more about this configuration and run it on-prem or in a private cloud.

All products are configured via APIs call, no manual tasks are needed. This makes it very easy to get started and have the setup up and running after just a few minutes.

**Overview**

The environment of this setup looks like this:

![alt overview](doc/simple_overview_02.png)

Please read the document first before starting to set it up.

**Good to know**

- This setup was developed on a MacBook. If this is used on a Windows machine, the provided instructions may not work as expected
- Download links can be found at the bottom of this document

## Download products and integration kits

This webinar uses the following products and integration kits:

**Products:**

- PingFederate 12.3
- PingDirectory 10.3
- PingAM 8.0.1
- PingDS 8.0

Download those products, place them here: **./products/...** and follow the **README.md** instructions per product.

Licenses for PingFederate and PingDirectory should be requested at your CSM.

Additionally, download the PingAM integration kit:

- **https://www.pingidentity.com/en/resources/downloads/pingfederate.html**
- tab **Add-Ons**
- **PingAM Integration Kit 1.2**

Unzip the file and place the extracted jar-file at this location:

- **docker-build/add-ons/pingfederate/pf-pingam-adapter-1.2.jar**

## Prepare your environment

The setup uses these technologies throughout:

- Docker
- Java11
- Maven
- Make (this is just for convenience)

**Note:** further down are instructions on how to build this setup if Maven is not available!

### Update hosts file

To simulate a more realistic environment update the local hosts file:

- `sudo vi /etc/hosts`
  - add **{your-current-ip-address} pf.webinar.local pd.webinar.local openam.webinar.local ds.webinar.local playground.webinar.local**
    - replace **{your-current-ip-address}** with the current IP address of your computer. Do NOT use *localhost* or *127.0.0.1*
    - example: **192.168.0.12 pf.webinar.local ...**

### Install Frodo

In order to use example PingAM trees/ journeys install **Frodo-cli**:

- `brew tap rockcarver/frodo-cli`
- `brew install frodo-cli`

**Tip:** To learn more about this tool, check the **Links** section further down.

### Create initial configuration files and private/public keys

In the current directory, open a terminal and run these commands:

- `sh initialize-dev-environment.sh`
  - creates an **.env** file for docker and is used as input for **initialize-dev-tls-keypair.sh**
  - it also contains the configuration details for this setup
  - running this script again pushes generated files to **dev/.env.bak**
  - the first time execution may display an error *mv: rename .env to dev/.env.bak: No such file or directory* which can be ignored
- `sh initialize-dev-tls-keypair.sh`
  - generates a keystore for this setup. Find generated files in **./dev**
  - the same keystore is used by PingFederate, PingAM, PingDirectory and PingDS
  - the first time execution may display an error *mv: rename ./dev/tlskey.p12 to ./dev/tlskey.p12.bak: No such file or directory* which can be ignored

## Build the setup

### Review and potentially update the default configuration

All configuration details are taken out of **.env**. The settings in this file are used throughout all configuration steps further down.

For the purpose of this setup all values can most likely stay as they are.

The only exceptions are these:

- update the file to configure and register an oauth client in PingFederate
- update the file to use the journey **WebinarJourneySNS** which requires AWS SNS credentials
  - this feature requires PingAM to be accessible from the internet

### Compile code and build docker images

- `make build_prereq`
  - this will create the docker images **webinar/tomcat:10, webinar/openjdk:17**
  - these are used later
  - this has to be executed only once

To build the java code, two options are available:

**Option 1:** Java and Maven are available:

- `make build_all`
  - builds all java code and docker images

**Option 2:** Maven is not available:

- `make build_builder`
  - this creates a docker image that contains Java and Maven
  - repeat this only if **pom.xml** changes or anything within **/libs**
- `make build_all_builder`
  - the same as **make build_all**, but it uses the builder image to compile the code

**Tip:** Wherever **make** is used, have a look into **Makefile** to learn more about the details.

As temporary docker images have been built, remove them by running this:

- `docker rmi $(docker images -f "dangling=true" -q)`
- `docker builder prune`

## Get the system up and running

These are the steps to launch and use the setup. Repeat these steps after stopping the setup.

All previous instructions are required once only and may be repeated if java code or the dockerfiles have been modified.

### Launch the setup

All docker images have been built and are ready to be launched for the first time:

- `docker compose up`
  - view the file **docker-compose.yml** for browser admin URLs  and username/ passwords for the different products

### Configure the running setup

At this point PingFederate and PingAM are basically empty containers (PingDirectory already contains example users and is ready to go).

Execute the next command whenever the setup was restarted:

- `make configure_setup`
  - this configures all products
  - run this in a separate terminal

Execute this once (the first time):

- `frodo conn add -k https://openam.webinar.local:8449/openam amAdmin 'Password1'`
  - It adds a connection for frodo and saves it here: **~/.frodo/Connections.json**
  - run `~/.frodo/Connections.json` to check if you already have an entry

Execute the next command whenever the setup was restarted:

- `make import_journeys`
  - this imports example journeys into PingAM

PingFederate and PingAM are now ready to be used. Find the admin URLs and usernames/ passwords in *docker-compose.yml*.

All journeys can be found here after they have been imported; their names start with **Webinar**:

- https://openam.webinar.local:8449/openam
- realm **webinar**  // the realm you configured in .env (PINGAM_REALM)
  - Authentication
    - Trees

### Stopping containers

Once done with this setup stop it by running the following in the active terminal:

- `ctrl+c`
- `docker compose down`

## Try out a journey

In this setup PingAM and PingFederate are connected to PingDirectory which includes 10 test users.

The usernames and passwords follow this pattern:

- **user.1/ password**
- **user.2/ password**
- **...**

### Provided example journeys

This setup comes with different PingFederate policies and PingAM journeys

|PingFederate policy| IDP Adapter| Description                                                                                                                                                                                                                                                            | Notes|
|-------------------|------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------|
|WebinarPingAMTree|PingAMIdpAdapter| PingFederate delegates authentication to PingAM. The adapter is configured to execute this journey in PingAM: **WebinarJourney**. This is the defautl policy and is active| Update the adapter configuration to execute other journeys. Choose from these: **WebinarJourneyOAthPush**, **WebinarJourneyWebAuthN** |
|WebinarPingAMBCATree|PingAMBackChannelAuthIdpAdapter| Use this with an authorization code flow that includes the parameter *login_hint*. PingFederate forwards the value to PingAM where the user has to provide his password. The adapter is configured to execute this journey in PingAM: **WebinarJourneyBackChannelAuth** ||
|WebinarMfaTree|PingAMMfaOnlyIdpAdapter| The user gets authenticated in PingFederate via the HTMLFormAdapter. Afterwards, the user is redirected to PingAM where an OTP based MFA flow is executed. The adapter is configured to execute this journey in PingAM: **WebinarJourneyMfaOnly**                      ||

**Tip:** Enable/ disable the policy you want to try out.

### Using an OAuth client

If you have configured an oauth client in **.env** open your client and select the **Login** button or whatever it may be that initiates an authorization_code flow.

PingFederate will execute the configured policy.

**Tip:** To install and use **OAuthPlayground** (which is a test/ demo OAuth client) follow these instructions:

- **docker-build/add-ons/oauthplayground/README.md**

### No OAuth client

Even without an oauth client it is possible to try out a journey. However, this does not use PingFederate.

Open a browser to invoke a journey without involving PingFederate:

- **https://openam.webinar.local:8449/openam/XUI/?realm=/webinar&service=WebinarJourney#login**

Replace **.../webinar** with your realm and **...=WebinarJourney** with another journey. Find available journey names in **Makefile** or in the PingAM UI.

The successful journey ends with a view of the users profile.

### Reconfigure PingFederate to invoke a different Journey

**Note:** This update is only useful in combination with an oauth client

In PingFederate go to **Authentication - IDP Adapters - PingAMIdpAdapter** and review its configuration.

Replace **JOURNEY** with **WebinarJourneyOAthPush**.

The next time a user authenticates, the OAth Push journey will be executed:

- authenticate using username/ password
- register device
- confirm verification code
- signed in

**Note:** The user will be asked to download the ForgeRock Authenticator app for that.

## A few other notes

If you wonder what docker images have been built throughout this setup, run this command:

- `docker images | grep webinar`  // the result includes the images IDs
- `docker rmi {image_id} {image_id} ...`  // use this to remove the images

If the build process fails, due to missing resources, try these first:

- `docker rmi $(docker images -f "dangling=true" -q)`
- `docker builder prune`

If nothing helps, and you run into space limitations you cannot solve:
- `docker system prune --all --force --volumes`
  - - WATCH OUT, this will blow away ALL images on your machine!

If you want to connect into a running image, use this:

- `docker exec -it {container_name} bash`
  - **{container_name}** -- see **docker-compose.yml**

The default directory for log files in PingAM

- `docker exec -it openamwebinarlocal bash`  // this takes you into the running container
- `/root/openam/var/`

To view log files in PingFederate:

- `docker exec -it pfwebinarlocal bash`  // the prompt is now within the running container
- `cd /opt/pingfederate/log`
- `ls -la`  // several log files are listed

When done with the evaluation of this setup it could be useful to remove the images as they are large in size:

- `docker rmi $(docker images --filter=reference="webinar/*" -q)`
  - any image tagged as **webinar/** will be deleted


## Links

- Download PingFederate:
  - [https://www.pingidentity.com/en/resources/downloads/pingfederate.html](https://www.pingidentity.com/en/resources/downloads/pingfederate.html)
  - the PingAM integration kit is already part of this setup, no need to download it separately
- Download PingAM:
  - [https://backstage.forgerock.com/downloads/browse/am/featured](https://backstage.forgerock.com/downloads/browse/am/featured)
- Download PingDirectory:
  - [https://www.pingidentity.com/en/resources/downloads/pingdirectory-downloads/previous-releases.html](https://www.pingidentity.com/en/resources/downloads/pingdirectory-downloads/previous-releases.html)
- PingFederate Swagger-UI:
  - [https://pf.webinar.local:9999/pf-admin-api/api-docs/#/](https://pf.webinar.local:9999/pf-admin-api/api-docs/#/)
- PingAM Swagger-UI:
  - [https://openam.webinar.local:8449/openam/ui-admin/#api/explorer/](https://openam.webinar.local:8449/openam/ui-admin/#api/explorer/)
- Frodo, a management tool for PingAM:
  - [https://github.com/rockcarver/frodo-cli?tab=readme-ov-file#quick-start](https://github.com/rockcarver/frodo-cli?tab=readme-ov-file#quick-start)
- Create a WebAuthN tree in PingAM
  - [https://backstage.forgerock.com/docs/am/7.4/authentication-guide/authn-mfa-webauthn.html](https://backstage.forgerock.com/docs/am/7.4/authentication-guide/authn-mfa-webauthn.html)
- Learn more about setting up a push notification service leveraging AWS SNS:
  - [https://backstage.forgerock.com/docs/am/7.4/authentication-guide/authn-mfa-trees-push.html](https://backstage.forgerock.com/docs/am/7.4/authentication-guide/authn-mfa-trees-push.html)
- Manage directory schemas with LDIF:
  - [https://backstage.forgerock.com/docs/am/7.4/install-guide/supported-ldifs.html](https://backstage.forgerock.com/docs/am/7.4/install-guide/supported-ldifs.html)
- PingIdentity on YouTube:
  - [@PingIdentityTV](https://www.youtube.com/@PingIdentityTV/videos)
- Webinar: This setup was used during a webinar and can be found here:
  - [https://www.pingidentity.com/en/company/upcoming-events/webinars/details/commId/620098.html](https://www.pingidentity.com/en/company/upcoming-events/webinars/details/commId/620098.html)

# Known issues

- sometimes (completely random as far as I am concerned) running `make import_journeys` fails. Wait 5-10 minutes and try again
- when images startup and PingDirectory or PingDS warn about limited resources (disk space), free up space by running commands as shown further up, stop the setup and launch again

# DISCLAIMER

This is not a production environment and is meant for educational purposes only.

It does not come with any kind of warranty, it is provided as is, it was not reviewed for potential performance or security weaknesses.

Logs are verbose to provide insight into the configuration and may include secrets used during this demo.

Use this project to evaluate this setup. Modify it as much or as little as you like.

Report any issues here in GitHub, PingIdentities support team cannot provide assistance of any kind.

This code is to be used exclusively in connection with Ping Identity Corporation software or services. Ping Identity Corporation only offers such software or services to legal entities who have entered into a binding license agreement with Ping Identity Corporation.

# License

This is licensed under the Apache License 2.0.
