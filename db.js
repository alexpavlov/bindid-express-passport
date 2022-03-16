const sqlite3 = require('sqlite3');
const mkdirp = require('mkdirp');

const path = 'var/db';
mkdirp.sync(path);

class AppDB {
    constructor() {
        this.db = new sqlite3.Database(`${path}/app.db`);
    }

    scaffold() {
        this.db.serialize(function () {
            this.run("CREATE TABLE IF NOT EXISTS users (password_hash BLOB, salt BLOB, email TEXT, name TEXT)");
            this.run('create unique index if not exists users_email_uindex on users (email)');
            this.run("CREATE TABLE IF NOT EXISTS federated_credentials (user_id INTEGER NOT NULL, provider TEXT NOT NULL, subject TEXT NOT NULL, PRIMARY KEY (provider, subject))");
        });
    }

    exec(query) {
        const that = this;
        return new Promise((resolve, reject) => {
            that.db.exec(query, function (err) {
                if (err) { reject(err); }
                else { resolve(); }
            });
        });
    }

    begin() {
        return this.db.exec('BEGIN');
    }

    rollback() {
        return this.db.exec('ROLLBACK');
    }

    commit() {
        return this.db.exec('COMMIT');
    }

    close() {
        const that = this;
        return new Promise((resolve, reject) => {
            that.db.close(function (err) {
                that.db = null;
                if (err) { reject(err); }
                else { resolve(); }
            });
        })
    }

    findFederatedCredentials(provider, provider_user_id) {
        const that = this;
        return new Promise((resolve, reject) => {
            that.db.get('SELECT * FROM federated_credentials WHERE provider = ? AND subject = ?',
                [provider, provider_user_id], function(err, credentials) {
                    if (err) { reject(err); }
                    else { resolve(credentials); }
                });
        });
    }

    findFederatedCredentialsByUserIdAndProvider(id, provider) {
        const that = this;
        return new Promise(((resolve, reject) => {
            that.db.all('SELECT rowid as id, * FROM federated_credentials WHERE user_id = ? AND provider = ?', [id, provider], function(err, credentials) {
               if (err) { reject(err); }
               else { resolve(credentials); }
            });
        }));
    }

    switchFederatedCredentials(from, to, provider) {
        const that = this;
        return new Promise((resolve, reject) => {
            that.db.run('UPDATE federated_credentials SET user_id = ? WHERE user_id = ? AND provider = ?', [
                to,
                from,
                provider
            ], function(err) {
                if (err) { reject(err) }
                else { resolve() }
            });
        });
    }

    createFederatedCredentials(local_user_id, provider, provider_user_id) {
        const that = this;
        return new Promise((resolve, reject) => {
            that.db.run('INSERT INTO federated_credentials (user_id, provider, subject) VALUES (?, ?, ?)', [
                local_user_id,
                provider,
                provider_user_id
            ], function(err) {
                if (err) { reject(err) }
                else { resolve(this.lastID) }
            });
        });
    }

    deleteFederatedCredentials(userId, provider) {
        const that = this;
        return new Promise((resolve, reject) => {
            that.db.run('DELETE FROM federated_credentials WHERE user_id = ? AND provider = ?', [userId, provider], function(err) {
                if (err) { reject(err); }
                else { resolve(); }
            });
        });
    }

    deleteAllFederatedCredentialsForUser(userId) {
        const that = this;
        return new Promise((resolve, reject) => {
            that.db.run('DELETE FROM federated_credentials WHERE user_id = ?', [userId], function(err) {
                if (err) { reject(err); }
                else { resolve(); }
            });
        });
    }

    findUserById(id) {
        const that = this;
        return new Promise((resolve, reject) => {
            that.db.get('SELECT rowid AS id, * FROM users WHERE ROWID = ?', [id], function(err, user) {
                if (err) { reject(err); }
                else { resolve(user); }
            });
        });
    }

    deleteUserById(id) {
        const that = this;
        return new Promise((resolve, reject) => {
            that.db.run('DELETE FROM users WHERE ROWID = ?', [id], function(err) {
                if (err) { reject(err); }
                else { resolve(); }
            });
        });
    }

    findUserByEmail(email) {
        const that = this;
        return new Promise((resolve, reject) => {
            that.db.get('SELECT rowid AS id, * FROM users WHERE email = ?', [email], function(err, user) {
                if (err) { reject(err); }
                else { resolve(user); }
            });
        });
    }

    createUser(email, name, password_hash, salt) {
        const that = this;
        return new Promise(function(resolve, reject) {
            that.db.run('INSERT INTO users (email, name, password_hash, salt) VALUES (?,?,?,?)', [email, name, password_hash, salt], function(err) {
                if (err) { reject(err) }
                else { resolve(this.lastID); }
            });
        });
    }

    updateUser(id, email, name) {
        const that = this;
        return new Promise((resolve, reject) => {
            that.db.run('UPDATE users SET name = ?, email = ? WHERE rowid = ?', [
                name,
                email,
                id
            ], function(err) {
                if (err) { reject(err) }
                else { resolve() }
            });
        });
    }
}

new AppDB().scaffold();

module.exports = AppDB;
