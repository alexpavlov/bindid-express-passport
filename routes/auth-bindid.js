const express = require('express');
const passport = require('passport');
const OpenIDConnectStrategy = require('passport-openidconnect');
const AppDB = require("../db");
const emailValidator = require("email-validator");
const passwordUtils = require("./password-utils");
const strategyName = 'bindid';
require("dotenv").config();
const ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn;

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
        scope: ['openid', 'email'],
        nonce: true,
        passReqToCallback: true
    },
    async function verify(req, issuer, uiProfile, idProfile, context, idToken, accessToken, refreshToken, params, cb) {

        let user, email;
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
                    return cb(new Error("internal error"));
                }

                // Check if it is a biometric enrollment for currently signed-in user
                if (req.user && req.user.id !== user.id) {
                    return cb(new Error("multiple accounts"))
                }
                return cb(null, {
                    id: user.id.toString(),
                    name: user.name,
                    email: user.email
                });
            }

            // The BindID user is logging in for the first time. Check if it is a biometric enrollment
            // for currently signed-in user
            if (req.user) {
                user = req.user;
            } else {
                // The email address provided by BindID is verified, so we can try to match a legacy
                // account by email.
                email = uiProfile._json.email_verified ? uiProfile._json.email : null;

                if (email) {
                    user = await db.findUserByEmail(email);
                }
            }

            if (user) {
                await db.createFederatedCredentials(user.id, issuer, idProfile.id);
                await db.commit();
                return cb(null, {
                    id: user.id.toString(),
                    name: user.name,
                    email: user.email
                });
            }

            // Verified email is not available, or user with matching email does not exist, and it is not
            // a biometric enrollment. Either way we need to create new user along with
            // federated credentials record.
            let rowId = await db.createUser(email, idProfile.displayName);
            await db.createFederatedCredentials(rowId, issuer, idProfile.id);
            await db.commit();
            return cb(null, {
                    id: rowId,
                    name: idProfile.displayName,
                    email: email,
                    new_bindid_account: true
                }
            );
        } catch (error) {
            try {
                await db.rollback();
            } catch (_) {
            }
            return cb(error);
        } finally {
            await db.close();
        }
    }
))

const router = express.Router();

router.post('/login/bindid', passport.authenticate(strategyName, {
    successRedirect: '/',
    failureRedirect: '/login'
}));

router.get('/redirect/bindid',
    passport.authenticate(strategyName, {failureRedirect: '/login', failureMessage: true}),
    function (req, res) {
        let user = req.session.passport.user;
        if (!user) {
            res.redirect('/login');
        } else if (req.session.passport.user.new_bindid_account) {
            res.redirect('/link/bindid')
        } else if (!user.name) {
            res.redirect('/profile');
        } else {
            res.redirect('/');
        }
    });

router.get('/link/bindid',
    ensureLoggedIn(),
    function(req, res, next) {
        if (!req.session.passport.user.new_bindid_account) {
            res.redirect('/');
        }
        res.render('link-bindid', {user: req.session.passport.user});
});

router.post('/link/bindid',
    ensureLoggedIn(),
    async function(req, res, next) {
        const currentUser = req.session.passport.user;
        if (!currentUser.new_bindid_account) {
            res.redirect('/');
            return;
        }
        if (req.body.skip) {
            req.session.passport.user.new_bindid_account = undefined;
            res.redirect(currentUser.name ? '/' : '/profile');
            return;
        }
        let email = req.body.email?.toLowerCase();
        if (!emailValidator.validate(email)) {
            res.render('link-bindid', {error: 'Missing or invalid email', request_body: req.body, user: currentUser});
            return;
        }
        if (!req.body.password) {
            res.render('link-bindid', {error: 'Missing password', request_body: req.body, user: currentUser});
            return;
        }
        try {
            var linkedUser = await passwordUtils.authenticateUser(email, req.body.password);
        } catch (error) {
            if (error instanceof passwordUtils.InvalidCredentialsError) {
                res.render('link-bindid', {error: 'Invalid credentials', user: currentUser, request_body: req.body});
                return;
            }
            throw error;
        }
        const db = new AppDB();
        try {
            // const user = await db.findUserByEmail(email);
            await db.switchFederatedCredentials(currentUser.id, linkedUser.id, process.env['BINDID_SERVER_URL']);
            await db.deleteUserById(currentUser.id);
            req.logout();
            req.login(linkedUser, {}, function() {
                res.redirect('/');
            });
        } finally {
            await db.close();
        }
    });

module.exports = router;
