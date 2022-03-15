const express = require('express');
const common = require('./password-utils');
const AppDB = require("../db");
const crypto = require("crypto");
const passport = require("passport");
const ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn;

const router = express.Router();

router.get('/enroll',
    ensureLoggedIn(),
    function (req, res, next) {
        res.render('enroll', {user: req.user});
    });

router.post('/enroll',
    ensureLoggedIn(),
    async function (req, res, next) {
        if (!req.body.password) {
            res.render('enroll', {error: 'Missing password', user: req.user});
            return;
        }
        const db = new AppDB();
        try {
            const user = await db.findUserById(req.user.id)
            if (!user) {
                res.render('enroll', {error: 'Internal Error, please retry later', user: req.user});
                return;
            }

            const passwordHash = await common.calculatePasswordHash(req.body.password, user.salt);
            if (!crypto.timingSafeEqual(user.password_hash, passwordHash)) {
                res.render('enroll', {error: 'Invalid password', user: user});
                return;
            }
            next();
        } finally {
            await db.close();
        }
    },
    passport.authorize('bindid', {
        successRedirect: '/',
        failureRedirect: '/enrollment-error'
    }));

module.exports = router;
