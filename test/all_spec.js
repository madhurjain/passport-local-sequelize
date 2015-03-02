/* global describe, before, beforeEach, it */

var Sequelize = require('sequelize'),
    should = require('should'),
    passportLocalSequelize = require('../lib/passport-local-sequelize');

var db = new Sequelize('test-db', 'user', 'pass', {
    dialect: 'sqlite',
    storage: 'test/test-db.sqlite',
    logging: false
});

var User;

var initDb = function (done) {
    User = passportLocalSequelize.defineUser(db, null, {
        iterations: 1000
    });

    // Authenticate the db
    db.authenticate()
        .complete(function (err) {
            if (err) {
                return done(err);
            }

            // Synchronize the db
            db.sync({ force: true }).complete(function (err) {
                done(err);
            });
        });
};

describe('Passport Local Sequelize', function () {
    before(function (done) {
        initDb(done);
    });

    beforeEach(function (done) {
        // Delete all users
        User.destroy({ truncate: true }).then(function() {
            done();
        }).catch(done);
    });

    it('can define a User schema for you', function () {
        should.exist(User);
    });

    it('can register and authenticate a user', function (done) {
        should.exist(User.register);

        User.register('someuser', 'somepass', function (err, registeredUser) {
            if (err) {
                return done(err);
            }

            registeredUser.get('username').should.equal('someuser');
            registeredUser.get('id').should.be.above(0);

            registeredUser.authenticate('badpass', function (err, authenticated) {
                if (err) {
                    return done(err);
                }

                authenticated.should.equal(false);

                registeredUser.authenticate('somepass', function (err, authenticatedUser) {
                    if (err) {
                        return done(err);
                    }

                    authenticatedUser.should.not.equal(false);

                    authenticatedUser.get('username').should.equal('someuser');

                    done();
                });
            });
        });
    });
});