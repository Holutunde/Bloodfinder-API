const User = require('../models/userSchema')
const bcrypt = require('bcryptjs')
const crypto = require('crypto')
const sendMail = require('../../utils/sendMail')
const generateToken = require('../../utils/generateToken')

const registerUser = async (req, res) => {
  const { email } = req.body
  const user = await User.findOne({ email })

  if (user && user.active) {
    return res.status(400).json({
      success: false,
      msg: 'Entered email id already registered with us. Login to continue',
    })
  } else if (user && !user.active) {
    return res.status(400).json({
      success: false,
      msg: 'Account created but not active',
    })
  }

  const newUser = await User.create({ ...req.body })

  //Generate 20 bit activation code
  crypto.randomBytes(20, function (err, buf) {
    //Activation link
    newUser.activeToken = buf.toString('hex')

    const link = `http://localhost:${process.env.PORT}/api/users/active/${newUser.activeToken}`

    newUser.save(function (err, user) {
      if (err) return next(err)
      res.status(201).json({
        success: true,
        email: newUser.email,
        username: newUser.username,
        password: newUser.password,
        msg: `User was registered successfully! Please check your email`,
      })
      sendMail.send({
        to: newUser.email,
        subject: 'Please confirm your account',
        html: `<h2>Email Confirmation</h2>
        <h4>Hello ${newUser.username}</h4>
        <p>Thank you for joining BloodFinder. Please confirm your email by clicking on the following link</p>
        <p>Please click <a href=${link}>here</a> to activate your account'</p>
        </div>`,
      })
    })
  })
}

const activeToken = async (req, res) => {
  //find corresponding user
  User.findOne(
    {
      activeToken: req.params.activeToken,
      // activeExpires: { gt: Date.now() },
    },
    function (err, user) {
      if (err) {
        console.log('no active token')
      }

      if (!user) {
        return res.status(400).json({
          success: false,
          msg: 'your activation link is invalid ',
        })
      }
      if (user.active == true) {
        return res.status(200).json({
          success: true,
          msg:
            'Your account is already activated, kindly go and login to use the app',
        })
      }

      //if user is not activated
      user.active = true
      user.save(function (err, user) {
        if (err) {
          console.log('Activation Unsuccessful')
        }
        //activation successful
        res.status(200).json({
          success: true,
          msg: 'Activation success',
        })
      })
    },
  )
}

const loginUser = async (req, res) => {
  const { email, password } = req.body

  if (!email || !password) {
    return res.status(400).json('Please provide email and password')
  }
  const logUser = await User.findOne({ email })

  if (!logUser) {
    return res.status(401).json('invalid email')
  }
  const confirmPassword = await logUser.confirmPassword(password)
  console.log(confirmPassword)
  if (logUser && confirmPassword) {
    res.json({
      email: logUser.email,
      username: logUser.username,
      token: generateToken(logUser._id),
      password: logUser.password,
    })
  }
}

// const userProfile = async (req, res) => {
//   const id = req.user._id
//   const user = await User.findById(id)

//   if (user) {
//     res.json(user)
//   } else {
//     res.status(404).json('User not found')
//   }
// }

// const updateUserProfile = async (req, res) => {
//   const id = req.user._id

//   const userUpdate = await User.findOneAndUpdate(
//     { _id: id },
//     { ...req.body },
//     {
//       new: true,
//       runValidators: true,
//     },
//   )
//   if (userUpdate) {
//     res.status(200).json(`user with name ${userUpdate.name} updated`)
//   } else {
//     res.status(404).json('User not found')
//   }
//}

module.exports = {
  registerUser,
  activeToken,
  loginUser,
  // userProfile,
  // updateUserProfile,
}
