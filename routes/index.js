const express = require('express');
const AppDB = require("../db");
const ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn;
require("dotenv").config();

const router = express.Router();

router.get('/',
    ensureLoggedIn(),
    async function (req, res, next) {
        let suggestBindID = false;
        const db = new AppDB();
        try {
            const credentials = await db.findFederatedCredentialsByUserIdAndProvider(req.user.id, process.env['BINDID_SERVER_URL']);
            if (credentials.length === 0) {
                suggestBindID = true;
            }
        } finally {
            await db.close();
        }
        res.render('index', {user: req.user, suggestBindID: suggestBindID});
    });

module.exports = router;
