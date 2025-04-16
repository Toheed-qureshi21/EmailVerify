import express from "express"
import { forgotPasswordController, getPasswordPage, login, logout, postResetPassword, resendVerificationLink, signup, toChangePassword, verifyEmailToken } from "../Controllers/User.controller.js";
import { checkIfUserLoggedIn, isAuthenticate } from "../Middlewares/auth.js";

const router = express.Router()

//! Static files
router.get("/login", checkIfUserLoggedIn, (req, res) => {

    return res.render("login.ejs");
})
router.get("/signup", checkIfUserLoggedIn, (req, res) => {
    return res.render("signup.ejs");
})
router.get("/home", isAuthenticate, (req, res) => {
    return res.render("home.ejs", { success_msg: req.flash("success_msg") });
})


router.get("/verify-email", isAuthenticate, (req, res) => {
    if (req.user.isEmail_Verified) {
        return res.redirect("/api/home");
    }
    return res.render("verify-email.ejs", {
        email: req.user.email
    })
});

router.get("/change-password", isAuthenticate, (req, res) => {
    if (!req.user) {
        return res.redirect("/api/login")
    }
    return res.render("change-password.ejs", { user: req.user, errors: req.flash('errors'), success_msg: req.flash("success_msg") });
})

// !Post routes
router.post("/login", login)
router.post("/signup", signup);
router.post("/resend-verification-link", isAuthenticate, resendVerificationLink)
router.post("/logout", isAuthenticate, logout)
router.get("/verify-email-link", verifyEmailToken)

router.post("/change-password", isAuthenticate, toChangePassword)

// ! Forgot passwords Routes
router.route("/reset-password").get((req, res) => {
    return res.render("forgot-password.ejs", {
        user: req.user || null,
        errors: req.flash("errors"),
        formSubmitted: req.flash("formSubmitted")[0] || false,
    });
});

router.route("/reset-password").post(forgotPasswordController);

router.get("/reset-password/:token",getPasswordPage)

router.post("/reset-password/:token",postResetPassword)

export default router;