const User = require('../models/User');
const jwt = require('jsonwebtoken');
const expressJwt = require('express-jwt');
const _ = require('lodash');
const { OAuth2Client } = require('google-auth-library')
const fetch = require('node-fetch');

// sendgrid
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// const {} = require('')

// Signup
// const signup = (req, res) => {
//     // console.log('REQ BODY ON SIGNUP', req.body);
//     const { name, email, password } = req.body;

//     User.findOne({ email }).exec((error, user) => {
//         if (user) {
//             return res.status(400).json({
//                 error: "Email is already in use"
//             })
//         }
//     })

//     let newUser = new User({ name, email, password })

//     newUser.save((error, success) => {
//         if (error) {
//             console.log('SIGNUP ERROR', error) 
//             return res.status(400).json({
//                 error: error
//             })
//         }
//         res.json({
//             message: 'Signup success! Please signin',
//         })
//     })
// }


const signup = (req, res) => {
    const { name, email, password } = req.body;

    User.findOne({ email }).exec((error, user) => {
        if (user) {
            return res.status(400).json({
                error: 'Email is already taken'
            });
        }

        const token = jwt.sign({ name, email, password }, process.env.JWT_ACCOUNT_ACTIVATION, { expiresIn: '10m' });

        const emailData = {
            from: process.env.EMAIL_FROM,
            to: email,
            cc: process.env.EMAIL_FROM,
            subject: `Account activation link`,
            html: `
                <h1>Please click <a href=${process.env.CLIENT_URL}/auth/activate/${token}>here</a> to activate your account</h1>
                <hr />
                <p>This email may contain sensetive information</p>
                <p>${process.env.CLIENT_URL}</p>
            `
        };

        sgMail
            .send(emailData)
            .then(sent => {
                // console.log('SIGNUP EMAIL SENT', sent)
                return res.json({
                    message: `Email has been sent to ${email}. Follow the instruction to activate your account`
                });
            })
            .catch(error => {
                // console.log('SIGNUP EMAIL SENT ERROR', error)
                return res.json({
                    message: error.message
                });
            });
    });
};

const accountActivation = (req, res) => {
    const { token } = req.body;

    if (token) {
        jwt.verify(token, process.env.JWT_ACCOUNT_ACTIVATION, function(error, decoded) {
            if (error) {
                // console.log('JWT VERIFY IN ACCOUNT ACTIVATION ERROR', error);
                return res.status(401).json({
                    error: 'Expired link. Signup again'
                });
            }

            const { name, email, password } = jwt.decode(token);

            const user = new User({ name, email, password });

            user.save((error, user) => {
                if (error) {
                    // console.log('SAVE USER IN ACCOUNT ACTIVATION ERROR', error);
                    return res.status(401).json({
                        error: 'Error saving user in database. Try signup again'
                    });
                }
                return res.json({
                    message: 'Signup success. Please signin.'
                });
            });
        });
    } else {
        return res.json({
            message: 'Something went wrong. Try again.'
        });
    }
};


const signin = (req, res) => {
    const { email, password } = req.body;

    // Check if user exists
    User.findOne({ email }).exec((error, user) => {
        if (error || !user) {
            return res.status(400).json({
                error: 'User with that email does not exsit. Please signup'
            })
        }
        // authenticate
        if (!user.authenticate(password)) {
            return res.status(400).json({
                error: 'Email and password does not match'
            })
        }

        // generate a token - send it to client
        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' })
        const { _id, name, email, role } = user;

        return res.json({
            token,
            user: { _id, name, email, role }
        });
    })
}

const requireSignin = expressJwt({
    secret: process.env.JWT_SECRET // req.user
})

const adminMiddleware = (req, res, next) => {
    User.findById({ _id: req.user._id }).exec((err, user) => {
        if (err || !user) {
            return res.status(400).json({
                error: "User not found"
            })
        }

        if (user.role !== "admin") {
            return res.status(400).json({
                error: "Admin resource. Access denied"
            })
        }

        req.profile = user;
        next()
    })
}

const forgotPassword = (req, res) => {
    const { email } = req.body;

    User.findOne({ email }, (err, user) => {
        if (err || !user) {
            return res.status(400).json({
                error: "User with that email does not exist"
            })
        }

        const token = jwt.sign({ _id: user._id, name: user.name }, process.env.JWT_RESET_PASSWORD, { expiresIn: '10m' });

        const emailData = {
            from: process.env.EMAIL_FROM,
            to: email,
            cc: process.env.EMAIL_FROM,
            subject: `Password Reset Link`,
            html: `
                <h1>
                    Please reset your password by clicking this 
                        <a href=${process.env.CLIENT_URL}/auth/password/reset/${token}>
                            link
                        </a>
                </h1>
                
                <hr />
                <p>This email may contain sensetive information</p>
                <p>${process.env.CLIENT_URL}</p>
            `
        };

        return user.updateOne({ resetPasswordLink: token }, (err, success) => {
            if (err) {
                // console.log('RESET PASSWORD LINK ERROR', err)
                return res.status(400).json({
                    error: 'Database connection error on user password forgot request'
                })
            } else {
                sgMail
                    .send(emailData)
                    .then(sent => {
                        // console.log('SIGNUP EMAIL SENT', sent)
                        return res.json({
                            message: `Email has been sent to ${email}. Follow the instructions to reset your password`
                        });
                    })
                    .catch(error => {
                        // console.log('SIGNUP EMAIL SENT ERROR', error)
                        return res.json({
                            message: error.message
                        });
                    });
            }
        })



    })
}

const resetPassword = (req, res) => {
    const { resetPasswordLink, newPassword } = req.body;

    if (resetPasswordLink) {
        jwt.verify(resetPasswordLink, process.env.JWT_RESET_PASSWORD, function(err, decoded) {
            if (err) {
                return res.status(400).json({
                    error: 'Expired link. Try agin'
                })
            }

            User.findOne({ resetPasswordLink }, (err, user) => {
                if (err || !user) {
                    return res.status(400).json({
                        error: 'Something went wrong. Try later'
                    })
                }

                const updatedFields = {
                    password: newPassword,
                    resetPasswordLink: ''
                }

                user = _.extend(user, updatedFields);

                user.save((err, result) => {
                    if (err) {
                        return res.status(400).json({
                            error: 'Error reseting user password'
                        })
                    }

                    res.json({
                        message: 'Great! Now you can login with your new password'
                    })
                })
            })
        })
    }

}

// client ID
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const googleLogin = (req, res) => {
    const { idToken } = req.body;

    client.verifyIdToken({ idToken, audience: process.env.GOOGLE_CLIENT_ID })
        .then(response => {
            console.log('GOOGLE LOGIN RESPONSE', response)
            const { email_verified, name, email } = response.payload;

            if (email_verified) {
                User.findOne({ email }).exec((err, user) => {
                    if (user) {
                        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' })
                        const { _id, email, name, role } = user;

                        return res.json({
                            token,
                            user: { _id, email, name, role }
                        })
                    } else {
                        let password = email + process.env.JWT_SECRET;

                        user = new User({ name, email, password });
                        user.save((err, data) => {
                            if (err) {
                                console.log('ERROR GOOGLE LOGIN ON USER SAVE', err)
                                return res.status(400).json({
                                    error: 'User signup failed with google'
                                })
                            }

                            const token = jwt.sign({ _id: data._id }, process.env.JWT_SECRET, { expiresIn: '7d' })
                            const { _id, email, name, role } = data;

                            return res.json({
                                token,
                                user: { _id, email, name, role }
                            })
                        })
                    }
                })
            } else {
                return res.status(400).json({
                    error: 'Google login failed. Try again'
                })
            }
        })
}

const facebookLogin = (req, res) => {
    console.log('FACEBOOK LOGIN REQ BODY', req.body);
    const { userID, accessToken } = req.body;

    const url = `https://graph.facebook.com/v2.11/${userID}/?fields=id,name,email&access_token=${accessToken}`;

    return (
        fetch(url, {
            method: 'GET'
        })
        .then(response => response.json())
        // .then(response => console.log(response))
        .then(response => {
            const { email, name } = response;

            User.findOne({ email }).exec((err, user) => {
                if (user) {
                    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' })
                    const { _id, email, name, role } = user;

                    return res.json({
                        token,
                        user: { _id, email, name, role }
                    })
                } else {
                    let password = email + process.env.JWT_SECRET;

                    user = new User({ name, email, password });
                    user.save((err, data) => {
                        if (err) {
                            console.log('ERROR FACEBOOK LOGIN ON USER SAVE', err)
                            return res.status(400).json({
                                error: 'User signup failed with facebook'
                            })
                        }

                        const token = jwt.sign({ _id: data._id }, process.env.JWT_SECRET, { expiresIn: '7d' })
                        const { _id, email, name, role } = data;

                        return res.json({
                            token,
                            user: { _id, email, name, role }
                        })
                    })
                }
            })
        })
        .catch(error => {
            res.json({
                error: 'Facebook login failed. Try later'
            })
        })
    )
}

module.exports = {
    signup,
    accountActivation,
    signin,
    requireSignin,
    adminMiddleware,
    forgotPassword,
    resetPassword,
    googleLogin,
    facebookLogin
}