# OAuthPlayground

OAuthPlayground is an example OAuth client that works with PingFederate. To build a docker container, please download it from here:

- **https://www.pingidentity.com/en/resources/downloads/pingfederate.html**
- open the **Add-Ons** tab, select **OAuthPlayground 4.4**

Unzip it and read the provided documents.

Place the zip file here:

- **docker-build/add-ons/oauthplayground**  // right next to this README file

In the root directory of this project run these commands to build and launch it:

- `make build_docker_playground`
- `docker compose -f docker-compose-playground.yml up`

Open a browser at: **https://playground.webinar.local:8448/OAuthPlayground**

Once in the OAuthPlayground UI, open the menu **Setup** (or **Settings** - **Redo the Setup**, if the setup button is not appearing) and register PingFederate as an authorization server:

- **Admin Host**: pf.webinar.local:9999
- **Certificate Errors**: Ignore
- **Admin Username**: Administrator
- **Admin Password**: Password1
- **Next**
- **CIBA**: Skip
- **Next**
- At this point OAuthPlayground registers several test clients at PingFederate
- **Done**

Now use an oauth client in OAuthPlayground:

- **Welcome**
- **Authorization Code**
- **Use OpenID Connect**  // for scope, add *email profile*
- **Submit**

The user will now be redirected to PingFederate and immediately to PingAM.

When the flow completes the resulting page will display an access_token on the right hand side of the screen.

Select **Get User Info** and the opening dialog displays details of the access_token.

The field **sub** contains the username that was used during the user journey in PingAM.

To stop OAuthPlayground use the terminal in which it was launched:

- `ctrl+c`
- `docker compose -f docker-compose-playground.yml down`