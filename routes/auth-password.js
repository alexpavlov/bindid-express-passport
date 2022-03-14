const express = require('express');
const passport = require('passport');
const passwordUtils = require('./password-utils');
const LocalStrategy = require('passport-local');
const emailValidator = require("email-validator");
const crypto = require('crypto');
const AppDB = require("../db");
const strategyName = 'password';

passport.use(strategyName, new LocalStrategy(async function verify(email, password, cb) {
    try {
        const user = await passwordUtils.authenticateUser(email, password);
        return cb(null, user);
    } catch (error) {
        if (error instanceof passwordUtils.InvalidCredentialsError) {
            return cb(null, null);
        }
        return cb(error, false)
    }
}));

const router = express.Router();

router.get('/login/password', function(req, res, next) {
    res.render('login', { error: "Invalid credentials"});
});

router.post('/login/password', passport.authenticate(strategyName, {
    successRedirect: '/',
    failureRedirect: '/login/password'
}));

router.get('/signup', function(req, res, next) {
    res.render('signup', {request_body: req.body});
});

router.post('/signup', async function (req, res, next) {
    let email = req.body.email?.toLowerCase();
    if (!emailValidator.validate(email)) {
        res.render('signup', {error: 'Missing or invalid email', request_body: req.body});
        return;
    }
    if (!req.body.password) {
        res.render('signup', {error: 'Missing password', request_body: req.body});
        return;
    }
    if (req.body.password !== req.body.repeat_password) {
        res.render('signup', {error: 'Passwords do not match', request_body: req.body});
        return;
    }

    const salt = crypto.randomBytes(16);

    try {
        const hashedPassword = await passwordUtils.calculatePasswordHash(req.body.password, salt);
        const db = new AppDB();
        try {
            if (await db.findUserByEmail(email)) {
                res.render('signup', {error: 'Email is taken already', request_body: req.body});
                return;
            }
            const id = await db.createUser(email, req.body.name, hashedPassword, salt)
            req.login({
                id: id,
                name: req.body.name,
                email: email
            }, function (err) {
                if (err) {
                    return next(err);
                }
                res.redirect('/profile');
            });
        } finally {
            await db.close();
        }
    } catch (error) {
        return next(error);
    }
});

module.exports = router;
