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

router.post('/unenroll',
    ensureLoggedIn(),
    async function (req, res, next) {
        const db = new AppDB();
        try {
            await db.deleteFederatedCredentials(req.user.id, process.env['BINDID_SERVER_URL'])
        } finally {
            await db.close();
        }
        res.redirect('/')
    });

router.post('/delete',
    ensureLoggedIn(),
    async function (req, res, next) {
        const db = new AppDB();
        try {
            await db.deleteAllFederatedCredentialsForUser(req.user.id)
            await db.deleteUserById(req.user.id)
        } finally {
            req.logout()
            await db.close();
        }
        res.redirect('/')
    });

module.exports = router;
