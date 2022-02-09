const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local');
const emailValidator = require("email-validator");
const crypto = require('crypto');
const AppDB = require("../db");
const strategyName = 'password';

async function calculatePasswordHash(password, salt) {
    return new Promise((resolve, reject) => {
        crypto.pbkdf2(password, salt, 310000, 32, 'sha256', function(err, hashedPassword) {
            if (err) {
                reject(err);
            } else {
                resolve(hashedPassword)
            }
        });
    });
}

passport.use(strategyName, new LocalStrategy(async function verify(email, password, cb) {
    const db = new AppDB();
    try {
        const user = await db.findUserByEmail(email);
        if (!user) { return cb(null, false); }
        try {
            const passwordHash = await calculatePasswordHash(password, user.salt);
            if (!crypto.timingSafeEqual(user.password_hash, passwordHash)) {
                return cb(null, false);
            }
        } catch (error) {
            return cb(error);
        }
        return cb(null, user);
    } finally {
        await db.close();
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
    let email = req.body.email.toLowerCase();
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
        const hashedPassword = await calculatePasswordHash(req.body.password, salt);
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