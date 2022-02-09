const express = require('express');
const passport = require('passport');
const AppDB = require("../db");
const ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn;

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
        cb(null, { id: user.id, name: user.name, email: user.email });
    });
});

passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
        return cb(null, user);
    });
});

const router = express.Router();

router.get('/login', function(req, res, next) {
    res.render('login');
});

router.post('/logout', function(req, res, next) {
    req.logout();
    res.redirect('/');
});

router.get('/profile',
    ensureLoggedIn(),
    function (req, res, next) {
        res.render('profile', {user: req.user});
    });

router.post('/profile',
    ensureLoggedIn(),
    async function (req, res, next) {
        var name = req.body.name;
        if (name) {
            const db = new AppDB();
            try {
                await db.updateUser(req.session.passport.user.id, req.session.passport.user.email, name)
                req.session.passport.user.name = name;
                res.redirect('/');
            } finally {
                await db.close();
            }
        }
    });

module.exports = router;
