const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const randomstring = require("randomstring");
const jwt = require('jsonwebtoken');

const User = require('../models/user');

require('dotenv').config();

const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_PASS
    }
});

const EMAIL_SECRET = randomstring.generate();

router.post('/signup', (req, res, next) => {
    User.findOne({ email: req.body.email })
        .exec()
        .then(user => {
            if (user) {
                return res.status(409).json({
                    message: 'Email already exists'
                })
            } else {
                bcrypt.hash(req.body.password, 10, (err, hash) => {
                    if (err) {
                        return res.status(500).json({
                            error: err
                        });
                    } else {
                        const user = new User({
                            _id: new mongoose.Types.ObjectId(),
                            email: req.body.email,
                            password: hash
                        });
                        user
                            .save()
                            .then(result => {
                                console.log(result);
                                res.status(201).json({
                                    message: 'User Signed Up'
                                });
                            })
                            .catch(err => {
                                res.status(500).json({
                                    error: err
                                });
                            });
                        jwt.sign({
                            email: user.email }, EMAIL_SECRET, (err, emailToken) => {
                            const url = `http://localhost:5000/user/confirmation/${emailToken}`;

                            transporter.sendMail({
                                to: user.email,
                                subject: 'Confirm Email',
                                html: `Please click this email to confirm your email: <a href="${url}">${url}</a>`
                            });
                        });
                    }
                })
            }
        })
});

router.get('/confirmation/:token', (req, res) => {
    try {
        const user = jwt.verify(req.params.token, EMAIL_SECRET);
        User.findOneAndUpdate({ email: user.email }, { $set: { confirmed: true }}, { new: true })
            .then(result => { res.send(result)});
    } catch (e) {
        res.send('error');
    }
});

module.exports = router;