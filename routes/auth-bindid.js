const express = require('express');
const passport = require('passport');
const OpenIDConnectStrategy = require('passport-openidconnect');
const AppDB = require("../db");
const strategyName = 'bindid';
require("dotenv").config();

passport.use(strategyName, new OpenIDConnectStrategy({
        issuer: process.env['BINDID_SERVER_URL'],
        authorizationURL: `${process.env['BINDID_SERVER_URL']}/authorize`,
        tokenURL: `${process.env['BINDID_SERVER_URL']}/token`,
        userInfoURL: `${process.env['BINDID_SERVER_URL']}/userinfo`,
        clientID: process.env['BINDID_CLIENT_ID'],
        clientSecret: process.env['BINDID_CLIENT_SECRET'],
        callbackURL: process.env['BINDID_REDIRECT_URI'],
        skipUserProfile: false,
        acrValues: 'ts.bindid.iac.email',
        scope: ['openid', 'email']
    },
    async function verify(issuer, uiProfile, idProfile, context, idToken, accessToken, refreshToken, params, cb) {

        let user;
        const db = new AppDB();

        try {
            await db.begin();
            let credentials = await db.findFederatedCredentials(issuer, uiProfile.id);

            if (credentials) {
                // The BindID user has previously logged in to the app.
                // Get the user account associated with the federated credentials and
                // log the user in.
                user = await db.findUserById(credentials.user_id);

                if (!user) {  // Data integrity issue
                    return cb("internal error");
                }
                return cb(null, user);
            }

            // The BindID user is logging in for the first time. We need to set up a local account.
            // Since email address provided by BindID is verified, we can try to match a legacy
            // account by email.
            let email = uiProfile._json.email_verified ? uiProfile._json.email : null;

            if (email) {
                user = await db.findUserByEmail(email);

                if (user) {
                    await db.createFederatedCredentials(user.id, issuer, idProfile.id);
                    await db.commit();
                    return cb(null, {
                        id: user.id.toString(),
                        name: user.name,
                        email: email
                    });
                }
            }

            // Verified email is not available, or user with matching email does not exist. Either way
            // we need to create a new user record.
            let rowId = await db.createUser(email, idProfile.displayName);
            await db.createFederatedCredentials(rowId, issuer, idProfile.id);
            await db.commit();
            return cb(null, {
                    id: rowId,
                    name: idProfile.displayName,
                    email: email
                }
            );

        } catch (error) {
            try { await db.rollback(); } catch (_) {}
            return cb(error);
        } finally {
            await db.close();
        }
    }
));

const router = express.Router();

router.post('/login/bindid', passport.authenticate(strategyName, {
    successRedirect: '/',
    failureRedirect: '/login'
}));

router.get('/redirect',
    passport.authenticate(strategyName, { failureRedirect: '/login', failureMessage: true }),
    function(req, res) {
        let user = req.session.passport.user;
        if (!user) {
            res.redirect('/login');
        } else if (!user.name) {
            res.redirect('/profile');
        } else {
            res.redirect('/');
        }
    });

module.exports = router;
