const express = require('express')
const router = express.Router()

const { 
    Signup, 
    Signin, 
    Signout,
    Forgot_password,
    Reset_Password   
} = require('../controllers/auth')
const { userSignupValidator } = require('../validator/index')

router.post('/signup', userSignupValidator, Signup)
router.post('/signin', Signin)
router.get('/signout', Signout)
router.post('/forgot/password', Forgot_password )
router.put('/reset/password', Reset_Password)

module.exports = router;