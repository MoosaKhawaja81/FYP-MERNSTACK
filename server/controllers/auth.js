const User = require('../models/user')
const Jwt = require('jsonwebtoken') // to generate signed token
const expressJwt = require('express-jwt') // for authorization check
const { errorHandler } = require('../helpers/dbErrorHandler');
const nodemailer = require('nodemailer')

exports.Signup = (req, res) => {
    // console.log("req.body", req.body);
    const user = new User(req.body);
    user.save((err, user) => {
        if(err) {
            return res.status(400).json({
                err: errorHandler(err)
            })
        }
        user.salt = undefined
        user.hashed_password = undefined
        res.json({
            user
        })
    })
};

exports.Signin = (req, res) => {
    // find the user based on email
    const { email, password } = req.body
    User.findOne({ email }, (err, user) => {
        if(err || !user ) {
            return res.status(400).json({
                error: 'User with that email does not exist. Please signup'
            })
        }

        // if the user is found make sure the email and password match
        // create authenticate method in user model 
        if(!user.authenticate(password)) {
            return res.status(401).json({
                error: 'Email and password do not match'
            })
        }
        // generate a signed token with user id and secret
        const token =  Jwt.sign({_id: user._id}, process.env.JWT_SECRET)
        // persist the token as 't' in cookie as expiry date
        res.cookie('t', token, {expire: new Date() + 9999})
        // return response with user and token to frontend client
        const { _id, name, email, role } = user
        return res.json({token, user: { _id, email, name, role }})

    })
}

exports.Signout = (req, res) => {
    res.clearCookie('t')
    res.json({message: 'Signout success'})
}

exports.requireSignin = expressJwt({
    secret: process.env.JWT_SECRET,
    algorithms: ["HS256"], // added later
    userProperty: "auth",
  });

exports.isAuth = (req, res, next) => {
    let user = req.profile && req.auth && req.profile._id == req.auth._id

    if(!user) {
        return res.status(403).json({
            error: 'Access denied'
        })
    }
    next()
}

exports.isAdmin = (req, res, next) => {
    if(req.profile.role === 0) {
        return res.status(403).json({
            error: 'Admin resource! Access denied'
        })
    }

    next()
}

exports.Forgot_password = (req, res) => {
    
    User.findOne({email: req.body.email}, (err, user) => {
        if(err || !user) {
            return res.status(422).json({
                error: 'Email with that id does not exist'
            })
        }
        res.json({
            user
        })

        if( err || !req.body.email ) {
            return res.status(422).json('Failed to Send Email')
        }
        else{
            var transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: 'kmtechnologo81@gmail.com',
                    pass: 'Lahore03106273291'
                }
            })
    
            var mailOptions = {
                from: 'kmtechnologo81@gmail.com',
                to: req.body.email,
                subject: 'Hello Khawaja moosa',
                html: '<a href="http://localhost:3000/reset/password">Click to this link to reset password</a>'
            };    
            transporter.sendMail(mailOptions, function(error, info){
                if (error) {
                  console.log(error);
                } else {
                  console.log('Email sent: ' + info.response);
                }
              });
        }

    })
}

exports.Reset_Password = (req, res) => {

    const { email, password } = req.body

    User.findOne({email}, (err, user) => {
        if(err || !user) {
            return res.status(400).json({
                error: 'User with email does not exist'
            })
        }
        if(!password) {
            return res.status(400).json({
                error: 'Please Enter New Password'
            })
        }
        else {
            user.password = password
        }
        user.save((err , updatedPassword) => {
            if(err) {
                console.log('User Update Error', err);
                return res.status(400).json({
                    error: 'User update password failed'
                })
            }
        })
        res.json(updatedPassword);
    })


}