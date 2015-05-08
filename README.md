# Passport-Local Sequelize
Passport-Local Sequelize is a [Sequelize](http://sequelizejs.com/) plugin 
that simplifies building username and password login with [Passport](http://passportjs.org)

This plugin is heavily inspired by [Passport-Local Mongoose](https://github.com/saintedlama/passport-local-mongoose) plugin.

# Installation

    $ npm install passport-local-sequelize

# Usage



```js
/* /models/user.js */

// Require all the stuff
var Sequelize = require('sequelize'),
	passportLocalSequelize = require('passport-local-sequelize');

// Setup sequelize db connection
var mydb = new Sequelize('mydb', 'myuser', 'mypass', {
	dialect: 'sqlite',

	storage: 'mydb.sqlite'
});

// A helper to define the User model with username, password fields
var User = passportLocalSequelize.defineUser(mydb, {
	favoriteColor: Sequelize.STRING
});

// --- OR ---

// Define a User yourself and use attachToUser

var User = mydb.define('User', {
	nick: Sequelize.STRING,
	myhash: Sequelize.STRING,
	mysalt: Sequelize.STRING
});

passportLocalSequelize.attachToUser(User, {
	usernameField: 'nick',
	hashField: 'myhash',
	saltField: 'mysalt'
});

module.exports = User;
```

Here's how to hook it all up to passport in your express app.

```js
var express = require('express'),
	passport = require('passport'),

	bodyParser = require('body-parser'),
	cookieParser = require('cookie-parser'),
	session = require('express-session'),

	User = require('./models/user'),

	app = express();


app.use(bodyParser());
app.use(require('connect-multiparty')());
app.use(cookieParser());
app.use(session({ secret: 'super-secret' }));

app.use(passport.initialize());
app.use(passport.session());

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());
```