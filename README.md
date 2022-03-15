# BindID - NodeJS/Express/Passport #



### Sample website featuring integration of BindID into Express/Passport environment. ###

#### Features ####
* BindID integration via [OpenID Connect](https://www.passportjs.org/packages/passport-openidconnect/) strategy
* Multiple scenarios for new and legacy user onboarding

### Setup ###

* Create an app using [BindID Admin Portal](https://admin.bindid-sandbox.io/console/#/applications).
     From the application settings, obtain the client credentials and configure redirect URL.
     See [BindID Admin Portal: Get Started](https://developer.bindid.io/docs/guides/admin_portal/topics/getStarted/get_started_admin_portal)
     for detailed instructions on configuring an app.
* Rename env-template file into .env and edit the .env to initialize variables with values taken from BindID Admin Portal
* Launch the server: _npm start_

### When in doubt ###

* Read the source code
* RTFM
* If none of the above works ping me at www.linkedin.com/in/pavlovalex
