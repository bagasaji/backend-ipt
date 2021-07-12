const { validationResult, header } = require('express-validator');

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const moment = require('moment');
const crypto = require('crypto');
const fs = require('fs');

const User = require('../models/user');
const { KJUR } = require('jsrsasign');

exports.signup = async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return;
    }

    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;

    try {
        const user = await User.find(email);
        if (user[0].length > 0) {
            const error = new Error('Email address already exist.');
            console.log(error.message);
            error.statusCode = 401;
            throw error;
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const userDetails = {
            name: name,
            email: email,
            password: hashedPassword
        };

        const result = await User.save(userDetails);

        res.status(201).json({ message: 'User registered!' });
        console.log("Register success!");
    } catch (error) {
        if (!error.statusCode) {
            error.statusCode = 500;
        }
        next(error);
    }
}

exports.login = async (req, res, next) => {
    const email = req.body.email;
    const password = req.body.password;

    const clientId = fs.readFileSync('D:/prototyping/prototype-ipt/clientId.txt', 'utf-8');
    const clientSecret = fs.readFileSync('D:/prototyping/prototype-ipt/clientSecret.txt', 'utf-8');
    const privateKey = fs.readFileSync('D:/prototyping/prototype-ipt/rsa_2048_priv.pem', 'utf-8');
    const publicKey = fs.readFileSync('D:/prototyping/prototype-ipt/rsa_2048_pub.pem', 'utf-8');
    const xTimestamp = moment().format();

    try {
        const user = await User.find(email);
        if (user[0].length !== 1) {
            const error = new Error('A user with this email could not be found.');
            console.log(error.message);
            error.statusCode = 401;
            throw error;
        }
        const storedUser = user[0][0];
        const isEqual = await bcrypt.compare(password, storedUser.password);
        if (!isEqual) {
            const error = new Error('Wrong password!');
            console.log(error.message);
            error.statusCode = 401;
            throw error;
        }

        // X-SIGNATURE RS256 + Base64
        const sign = new KJUR.crypto.Signature({ "alg": "SHA256withRSA" });
        sign.init(privateKey);
        sign.updateString(clientId + '|' + xTimestamp);
        const signatureAuthorization = sign.sign();
        console.log("Signature Authorization generated!");

        const sig = new KJUR.crypto.Signature({ "alg": "SHA256withRSA" });
        sig.init(publicKey);
        sig.updateString(clientId + '|' + xTimestamp);
        const isValid = sig.verify(signatureAuthorization);
        if (!isValid) {
            const error = new Error("Invalid Signature Authorization!");
            console.log(error.message);
            error.statusCode = 401;
            throw error;
        }
        console.log("Signature Authorization valid!");

        //ACCESS TOKEN 
        const token = jwt.sign(
            {
                "X-TIMESTAMP": xTimestamp,
                "X-CLIENT-KEY": clientId,
                "X-SIGNATURE": signatureAuthorization,
                "body": {
                    "grantType": "client_credentials"
                }
            },
            clientSecret,
            {
                expiresIn: '1h'
            }
        )
        if (!token) {
            const error = new Error("Access Token not generated!");
            console.log(error.message);
            error.statusCode = 401;
            throw error;
        }
        console.log("Access Token generated!" + token);

        // X-SIGNATURE HS512 + Base64
        const body = req.body;
        const bodySignature = crypto.createHash('sha256').update(body.toString()).digest('hex');

        const signatureSaldo = KJUR.jws.JWS.sign(null, { alg: "HS512" }, "POST" + ':' + "/bi/openapi/balance-inquiry" + ':' + token + ':' + bodySignature.toLowerCase() + ':' + xTimestamp, { "utf8": clientSecret });
        if (!signatureSaldo) {
            const error = new Error("Signature Saldo not generated!");
            console.log(error.message);
            error.statusCode = 401;
            throw error;
        }
        console.log("Signature Saldo generated!" + signatureSaldo);

        res.status(200).json({
            token: token,
            userId: storedUser.id,
            name: storedUser.name
        });
        console.log("Login success!");

    } catch (error) {
        if (!error.statusCode) {
            error.statusCode = 500;
        }
        next(error);
    }
}