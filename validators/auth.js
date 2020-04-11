const { check } = require('express-validator');

const userSignupValidator = [
    check('name')
        .not()
        .isEmpty()
        .withMessage('You name is required'),
    check('email')
        .isEmail()
        .withMessage('Please insert a valid email address'),
    check('password')
        .isLength({ min: 6 })
        .withMessage('Password must be at least 6 characters long')
]

const userSigninValidator = [
    check('email')
        .isEmail()
        .withMessage('Please insert a valid email address'),
    check('password')
        .isLength({ min: 6 })
        .withMessage('Password must be at least 6 characters long')
]

module.exports = {
    userSignupValidator, userSigninValidator
}