const express = require('express');
const ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn;

const router = express.Router();

router.get('/',
    ensureLoggedIn(),
    function (req, res, next) {
        res.render('index', {user: req.user});
    });

module.exports = router;
