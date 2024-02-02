const express = require("express");
const router = express.Router();
const auth = require("../../middleware/authentication");

const {
  registerUser,
  activeToken,
  loginUser,
  generateOTP,
} = require("../controllers/user");

router.route("/register").post(registerUser);
router.route("/login").post(loginUser);
router.route("/otp/generate").post(generateOTP);
// router.route('/profile').get(auth, userProfile).patch(auth, updateUserProfile)
router.route("/active/:activeToken").get(activeToken);

module.exports = router;
