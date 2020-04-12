const express = require('express');
const router = express.Router();

// Import Controllers
const { signup, accountActivation, signin, forgotPassword, resetPassword } = require('../controllers/auth');

// Import Validators
const { userSignupValidator, userSigninValidator, forgotPasswirdValidator, resetPasswirdValidator } = require('../validators/auth');
const { runValidation } = require('../validators');

router.post('/signup', userSignupValidator, runValidation, signup);
router.post('/account-activation', accountActivation);
router.post('/signin', userSigninValidator, runValidation, signin);

// forgot reset passowrd
router.put('/forgot-password', forgotPasswirdValidator, runValidation, forgotPassword);
router.put('/reset-password', resetPasswirdValidator, runValidation, resetPassword);

module.exports = router;