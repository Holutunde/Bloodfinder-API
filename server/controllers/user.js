const User = require("../models/userSchema");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const OTPAuth = require("otpauth");
const validator = require("email-validator");
const sendMail = require("../../utils/sendMail");
const generateToken = require("../../utils/generateToken");
const { encode } = require("hi-base32");

const registerUser = async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (user && user.active) {
    return res.status(400).json({
      success: false,
      msg: "Entered email already registered. Login to continue.",
    });
  } else if (user && !user.active) {
    return res.status(400).json({
      success: false,
      msg: "Account created but not active.",
    });
  }

  const newUser = await User.create({ ...req.body });
  const response = validator.validate(newUser.email);

  if (response) {
    // Generate 20-bit activation code
    const activationToken = crypto.randomBytes(20).toString("hex");
    newUser.activeToken = activationToken;

    const link = `http://localhost:${process.env.PORT}/api/users/active/${activationToken}`;

    await newUser.save();

    res.status(201).json({
      success: true,
      email: newUser.email,
      username: newUser.username,
      msg: "User was registered successfully! Please check your email.",
    });

    sendMail.send({
      to: newUser.email,
      subject: "Please confirm your account",
      html: `<h2>Email Confirmation</h2>
          <h4>Hello ${newUser.username}</h4>
          <p>Thank you for joining BloodFinder. Please confirm your email by clicking on the following link:</p>
          <p>Please click <a href=${link}>here</a> to activate your account.</p>
          </div>`,
    });
  }
};

const activeToken = async (req, res) => {
  //find corresponding user
  User.findOne(
    {
      activeToken: req.params.activeToken,
      // activeExpires: { gt: Date.now() },
    },
    function (err, user) {
      if (err) {
        console.log("no active token");
      }

      if (!user) {
        return res.status(400).json({
          success: false,
          msg: "your activation link is invalid ",
        });
      }
      if (user.active == true) {
        return res.status(200).json({
          success: true,
          msg: "Your account is already activated, kindly go and login to use the app",
        });
      }

      //if user is not activated
      user.active = true;
      user.save(function (err, user) {
        if (err) {
          console.log("Activation Unsuccessful");
        }
        //activation successful
        res.status(200).json({
          success: true,
          msg: "Activation success",
        });
      });
    }
  );
};

const loginUser = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json("Please provide email and password");
  }
  const logUser = await User.findOne({ email });

  if (!logUser) {
    return res.status(401).json("invalid email");
  }

  const isPasswwordConfirmmedd = await logUser.confirmPassword(password);
  if (!logUser.active) {
    res.status(401).json({
      success: false,
      msg: "email is not activated",
    });
  } else {
    res.status(200).json({
      email: logUser.email,
      username: logUser.username,
      token: generateToken(logUser._id),
      password: logUser.password,
      otp_enabled: logUser.otp_enabled,
    });
  }
};

const forgotPassword = async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json(`user with this ${user} not found`);
  }
  const token = generateToken(user._id);
  if (!token) {
    return res.status(401).json("token cannot be verified");
  }
  res.status(200).json({ newpasswordToken: token });
};

const changePassword = async (req, res) => {
  const { newpassword, confirmpassword, token } = req.body;

  try {
    if (newpassword != confirmpassword) {
      return res.status(400).json("both passwords are not the same");
    }
    const { email } = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ email });
    user.password = newpassword;
    user.save();
    res.status(200).send("password changed");
  } catch (err) {
    return res.status(401).json("invalid Token");
  }
};

const generateRandomBase32 = () => {
  const buffer = crypto.randomBytes(15);
  const base32 = encode(buffer).replace(/=/g, "").substring(0, 24);
  return buffer;
};

const nodemailer = require("nodemailer");

const generateOTP = async (req, res) => {
  const email = req.body.email;

  const user = await User.findOne({ email });

  if (!user) {
    return res.status(404).json({
      success: false,
      message: `User with ${email} does not exist`,
    });
  }

  const base32_secret = generateRandomBase32();

  const totp = new OTPAuth.TOTP({
    issuer: "2FA Test",
    label: `2FA Test: @${user.username}`,
    algorithm: "SHA1",
    digits: 6,
    period: 60,
    secret: "NB2W45DFOIZA",
  });

  const otp = totp.generate();

  user.otp_auth_url = totp.toString();
  user.otp_base32 = base32_secret;

  // Assuming you have a configured nodemailer transporter
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: process.env.MAIL_USER,
      pass: process.env.MAIL_PASSWORD,
    },
  });

  await transporter.sendMail({
    from: process.env.FROM_MAIL,
    to: user.email,
    subject: "Your OTP for 2FA",
    text: `Your OTP for 2FA is: ${otp}`,
  });

  await user.save();

  res.status(200).json({
    email: user.email,
    username: user.username,
    otpauth_url: user.otp_auth_url,
    base32_secret: user.otp_base32,
    message: "OTP sent successfully via email",
  });
};

const verifyOTP = async (req, res) => {
  const { email } = req.body;
  const token = req.params.token;
  const user = await User.findOne({ email });

  if (!user) {
    return res.status(404).json({
      success: false,
      message: `User with ${email} does not exist`,
    });
  }

  const totp = new OTPAuth.TOTP({
    issuer: "2FA Test",
    label: `2FA Test: @${user.username}`,
    algorithm: "SHA1",
    digits: 6,
    period: 60,
    secret: "NB2W45DFOIZA",
  });
  console.log("totp", totp);

  const delta = totp.validate({ token });
  console.log("delta", delta);

  if (delta === null) {
    return res.status(401).json({
      status: "fail",
      message: "Invalid OTP",
    });
  }

  user.otp_enabled = true;
  user.otp_verified = true;
  await user.save();

  res.status(200).json({
    otp_verified: true,
    user: {
      id: user.id,
      name: user.username,
      email: user.email,
      otp_enabled: user.otp_enabled,
    },
  });
};

module.exports = {
  registerUser,
  activeToken,
  loginUser,
  forgotPassword,
  changePassword,
  generateOTP,
  verifyOTP,
};
