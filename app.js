const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const passport = require('passport');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const indexRouter = require('./routes/index');
const authCommonRouter = require('./routes/auth-common');
const authPasswordRouter = require('./routes/auth-password');
const authBindIDRouter = require('./routes/auth-bindid');
const enrollmentRouter = require('./routes/enroll');
const mkdirp = require("mkdirp");
require("dotenv").config();

const requiredEnvParams = [
  'BINDID_SERVER_URL',
  'BINDID_CLIENT_ID',
  'BINDID_CLIENT_SECRET',
  'BINDID_REDIRECT_URI',
  'PORT'
];

var killSwitch = false;

requiredEnvParams.forEach((param) => {
  if (!process.env[param] || process.env[param].length === 0) {
    killSwitch = true;
    console.warn(
        `FATAL: Missing mandatory environment variable ${param}`
    );
  }
});

if (killSwitch) {
  process.exit(1);
}

for (const param of requiredEnvParams) {
  if (!process.env[param] || process.env[param].length === 0) {
    console.warn(
        `WARNING: Parameter ${param} is undefined, unexpected behaviour may occur, check your environment file`
    );
  }
}

const sessionDBPath = 'var/db';
mkdirp.sync(sessionDBPath);

const app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSIONSECRET || 'abracadabra19',
  resave: false,
  saveUninitialized: false,
  store: new SQLiteStore({ db: 'sessions.db', dir: sessionDBPath })
}));
app.use(passport.authenticate('session'));

app.use('/', indexRouter);
app.use('/', authCommonRouter);
app.use('/', authPasswordRouter);
app.use('/', authBindIDRouter);
app.use('/', enrollmentRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {

  if (err.message === 'multiple accounts') {
    res.render('enroll', {error: 'You have already activated biometric authentication for another account', user: req.user});
    return;
  }

  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

console.log(`The app is listening on port ${process.env.PORT}`)

module.exports = app;
