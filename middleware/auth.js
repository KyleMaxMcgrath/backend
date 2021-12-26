const jwt = require("jsonwebtoken");
const ExpressError = require('../expressError')
const db = require("../db");

const SECRET_KEY = `ThisIsASecret`;
const JWT_OPTIONS = { expiresIn: 60 * 60 };

function authenticateJWT(req, res, next) {
    try {
        const tokenFromBody = JSON.parse(req.body.token);
        const payload = jwt.verify(tokenFromBody, SECRET_KEY);
        req.user = payload;
        return next();
    } catch (err) {
        return next();
    }
};

function ensureLoggedIn(req, res, next) {
    if (!req.user) {
        const err = new ExpressError("Unauthorized", 401);
        return next(err);
    } else {
        return next();
    }
};

function ensureAdmin(req, res, next) {
    console.log(req.user);
    if (!req.user || !req.user.isAdmin) {
        const err = new ExpressError("Unauthorized", 401);
        return next(err);
    } else {
        return next();
    }
};

module.exports = {authenticateJWT, ensureLoggedIn, ensureAdmin, SECRET_KEY};