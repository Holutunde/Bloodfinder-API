const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')

const UserSchema = new mongoose.Schema({
  username: {
    type: 'string',
    required: true,
  },
  email: {
    type: 'string',
    required: true,
    match: [
      /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
      //validator that check if the value matches the given regular expression
      'Please provide a valid email',
    ],
    unique: true,
  },
  password: {
    type: String,
    required: true,
    minlength: 5,
  },
  active: {
    type: Boolean,
    default: false,
  },
  activeToken: {
    type: 'string',
    unique: true,
  },
})

UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    next()
  }
  const salt = await bcrypt.genSalt(10)
  this.password = await bcrypt.hash(this.password, salt)
})

UserSchema.methods.confirmPassword = async function (accessPassword) {
  return await bcrypt.compare(accessPassword, this.password)
}

module.exports = mongoose.model('User', UserSchema)
