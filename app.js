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
const mkdirp = require("mkdirp");

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

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

const port = process.env.PORT || 8080;

app.listen(port, () => {
  console.log(`Tha app is listening on port ${port}`)
})

module.exports = app;
