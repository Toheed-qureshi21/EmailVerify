import fs from "fs/promises";
import path from "path"
import ejs from "ejs"
import bcrypt from "bcryptjs"
import { User } from "../Models/User.model.js"
import { generateToken } from "../Utils/generateToken.js";
import { VerifyEmail } from "../Models/VerifyEmail.model.js";

import { sendEmail } from "../Libs/nodemailer.js";
// import { sendEmail } from "../Libs/resend.js";
import { comparePassword, createResetPasswordLink, createVerifyEmailLink, findVerificationEmailToken, generateVerificationToken, getResetPasswordData, toHashPassword, updatePassword, verifyUserEmailAndUpdate } from "../Services/auth.service.js";
import mjml2html from "mjml";

import session from "express-session";
import { ForgotPassword } from "../Models/ForgotPassword.model.js";
import { decodeIdToken, generateCodeVerifier, generateState } from "arctic";
import { google } from "../Libs/OAuth/google.js";
import { OAuthAccount } from "../Models/OAuthAcconts.model.js";
export const signup = async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ error: "All fields are required" });
        }
        const isUserExist = await User.findOne({ email });
        if (isUserExist) {
            return res.status(400).json({ error: "User already exist" });
        }
        const hashedPassword = await toHashPassword(password, 12)
        const user = await User.create({
            name,
            email,
            password: hashedPassword
        });
        generateToken(res, user._id);
        return res.redirect("/api/home");


    } catch (error) {
        console.log(error);
        return res.status(500).json({ error: "Internal server error" });

    }
}
export const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email ) {
            return res.status(400).json({ error: "All fields are required" });
        }
        
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: "User not found" });
        }
        if (!user.password) {
            req.flash("errors", "You have created account with social login . Please log in with social account");
            return res.redirect("/api/login");
        }
        const isPasswordMatch = await comparePassword(password, user.password);
        if (!isPasswordMatch) {
            return res.status(400).json({ error: "Invalid credentials" });
        }
        generateToken(res, user._id);
        res.redirect("/api/home");

    } catch (error) {
        console.log(error);
        return res.status(500).json({ error: "Internal server error" });
    }
}

export const logout = async (req, res) => {
    try {
        const userId = req.user._id;

        // Check if user logged in with Google
        const googleOAuthAccount = await OAuthAccount.findOne({
            userId: userId,
            provider: "google",
        });

        // Remove OAuth record if you want to unlink (optional)
        if (googleOAuthAccount) {
            await OAuthAccount.deleteOne({ _id: googleOAuthAccount._id });
        }

        // Clear cookies
        res.clearCookie("token", { path: "/" });
        res.clearCookie("isLoggedIn", { path: "/" });
        res.clearCookie("google_oauth_code_verifier", { path: "/" });
        res.clearCookie("google_oauth_state", { path: "/" });

        // Destroy session
        req.session?.destroy?.();

        // Conditionally redirect
        if (googleOAuthAccount) {
            // Google user: redirect to frontend route that handles Google logout
            return res.redirect("https://accounts.google.com/Logout")
        } else {
            // Normal user: redirect directly to login
            return res.redirect("/api/login");
        }
    } catch (error) {
        console.error("Logout error:", error);
        return res.status(500).json({ error: "Internal server error" });
    }
};



export const resendVerificationLink = async (req, res) => {
    try {
        if (!req.user) {
            return res.redirect("/login");
        }
        if (req.user.isEmail_Verified) {
            return res.redirect("/api/home");
        }
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }
        const randomToken = generateVerificationToken();
        await VerifyEmail.deleteMany({ userId: user._id });
        await VerifyEmail.create({
            userId: user._id,
            token: randomToken
        });
        // ! Creating url with random token

        const verifyEmailLink = createVerifyEmailLink(user.email, randomToken);

        // ! Using mjml email template instead of html
        const mjmlTemplate = await fs.readFile(path.join(import.meta.dirname, "../emails/verify-email.mjml"), "utf-8");
        // ! Step 2:- To replace placeholder in .mjml file with actual values of links and randomToken
        const filledMjmlTemplate = ejs.render(mjmlTemplate, {
            code: randomToken,
            link: verifyEmailLink
        })

        //! Step:-3 To convert mjml file to html file
        const htmlOutputOfMjmlFile = mjml2html(filledMjmlTemplate).html;


        //! Now we have to send email in user gmail using resend instead of nodemailer
        // ! So this sendEmail function of nodemailer get replaced by sendEmail function of resend
        // ! Full file of nodemailer is in Libs/nodemailer.js gets commented

        sendEmail({
            to: user.email,
            subject: "Verify your email",
            html: htmlOutputOfMjmlFile
        }).catch((err) => {
            console.log(err);
            return res.status(500).json({ error: "Internal server error" });
        });
        return res.redirect("/api/verify-email");

    } catch (error) {
        console.log(error);
        return res.status(500).json({ error: "Internal server error" });
    }
}
// verifyEmailToken

export const verifyEmailToken = async (req, res) => {

    const { token } = req.query;


    const tokenOtp = await findVerificationEmailToken(token);
    if (!tokenOtp) {
        return res.status(400).json({ error: "Invalid token" });
    }
    await verifyUserEmailAndUpdate(tokenOtp)
    return res.redirect("/api/home");

}

// ! Change password functionality

export const toChangePassword = async (req, res) => {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    if (!currentPassword || !newPassword || !confirmPassword) {
        req.flash("errors", "All fields are required");
        return res.redirect("/api/change-password");
    }
    if (newPassword !== confirmPassword) {
        req.flash("errors", "New password and confirm password does not match");
        return res.redirect("/api/change-password");
    }
    const userId = req.user._id.toString()
    const user = await User.findOne({ _id: userId });
    if (!user) {
        req.flash("errors", "User not found")
        return res.redirect("/api/change-password")
    }

    const isPasswordMatch = await comparePassword(currentPassword, user.password);
    if (!isPasswordMatch) {
        req.flash("errors", "Current password does not match")
        return res.redirect("/api/change-password")
    }
    await updatePassword(userId,currentPassword,12);
    req.flash("success_msg", "Password Updated Successfully");
    return res.redirect("/api/home");

}

// ! Forgot password
export const forgotPasswordController = async (req, res) => {
    const { email } = req.body;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!email || !emailRegex.test(email)) {
        req.flash("errors", "Invalid email");
        return res.redirect("/api/reset-password");
    }

    const user = await User.findOne({email});

    // ! Step -1 --> Generates random Token of 64 characters
    // ! Step -2 --> Converts that random token into hash
    // ! Step -3 --> Clear all previous token_hash of that user
    // ! Step -4 --> Insert the token_hash into ForgotPassword.model
    // ! Step -5 --> Returns link

    const resetPasswordLink = await createResetPasswordLink({userId:user._id});

    // ! MJML template for sending that link to user gmail
    // !Step -1 --> mjml file ko read karna hoga
    const mjmlTemplate = await fs.readFile(path.join(import.meta.dirname,"../emails/forgot-password.mjml"),"utf-8");

    // !Step -2 --> then  us file ke dynamic  placeholder ko pass karna hoga
    const filledMjmlTemplate = ejs.render(mjmlTemplate,{
        name:user.name,
        link:resetPasswordLink,
    });

    // !Step -3 --> then us mjml file ko html me convert karna hoga

    const htmlOutputOfMjmlFile = mjml2html(filledMjmlTemplate).html;

    // ! send email to user email

    await sendEmail({
        to:user.email,
        subject:"Reset password link",
        html:htmlOutputOfMjmlFile
    });

    return res.redirect("/api/reset-password");

}

export const getPasswordPage = async(req,res) => {
    const {token} = req.params;
    const passwordResetData = await getResetPasswordData(token)
    if (!passwordResetData) {
        return res.render("wrong-reset-password")
    }
    return res.render("reset-password",{
        formSubmitted:req.flash("formSubmitted")[0],
        errors:req.flash("errors"),
        token,
    });
}

export const postResetPassword =async (req,res) => {


    const {newPassword,confirmPassword} = req.body;
    if (!newPassword || !confirmPassword || newPassword!==confirmPassword) {
        req.flash("errors","Both password fields are required")
        return res.redirect("/api/reset-password/:token")
    }
    const {token} = req.params;
    const passwordResetData = await getResetPasswordData(token);
    const userId = passwordResetData.userId;
    await ForgotPassword.deleteMany({userId});
    await updatePassword(userId,newPassword,12);
    return res.redirect("/api/login");
}   

export const getGooglePage = async (req,res) => {

    // To create authorization url
    const state = generateState();
    const codeVerifier = generateCodeVerifier();
    const scopes = ["openid", "profile","email"]
    const url = google.createAuthorizationURL(state,codeVerifier,scopes,{
        prompt: "consent select_account",
        access_type: "offline",
        include_granted_scopes: false,
    });
    const cookieConfig = {
        httpOnly: true,
        secure: false,
        sameSite: "lax",
        maxAge:100*60*60*1000,
    }
    res.cookie("google_oauth_state",state,cookieConfig)
    res.cookie("google_oauth_code_verifier",codeVerifier,cookieConfig)
    console.log("Generated URL: ", url.toString());

    return res.redirect(url.toString());
}

// export const getGoogleCallback = async(req,res)=>{
//     const {state,code} = req.query;
//     const {google_oauth_state:storedStateInCookie,google_oauth_code_verifier:storedCodeVerifier} = req.cookies;
//     if(!state||!code||!storedStateInCookie||!storedCodeVerifier||state!==storedStateInCookie){
//         req.flash("errors","Invalid state");
//         return res.redirect("/api/login");
//     }
//     let tokens;
//     try {
//         tokens = await google.validateAuthorizationCode(code,storedCodeVerifier);
//         const claims = decodeIdToken(tokens.idToken());
//         console.log('State from request:', state);
// console.log('Stored state in cookie:', storedStateInCookie);
// console.log('Decoded token:', claims);

//         const {sub:googleUserId,email,name} = claims;
//         console.log("GOOGLE USER ID ",`${googleUserId}`);
        

//         // Condition --> 1 If user already exist with gooogle's oauth linked account
//         let oauthAccount = await OAuthAccount.findOne({
//             provider: "google",
//             providerAccountId: googleUserId // or google profile id from OAuth
//           });
//           console.log(oauthAccount);
//           if (!oauthAccount) {
//             // req.flash("errors","No account found");
//             // return res.redirect("/api/login");
//         }
//         let user = await User.findById(oauthAccount.userId).select("-password");
          

//         // Condition --> 2 If user already exist with same email but google ouath is not linked to that account
//         if(user && !user.providerAccountId){
//             await OAuthAccount.create({userId:user._id,provider:"google",providerAccountId:googleUserId});
//             console.log("Linked Google account to user:", user);
//         }
//         // Condition --> 3 If user does not exist
//         if (!user) {
//             user = await User.create({name,email,isEmail_Verified:true});
//             await OAuthAccount.create({userId:user._id,provider:"google",providerAccountId:googleUserId});
//         }
//         generateToken(res,user._id);
//         return res.redirect("/api/home");
//     } catch (error) {
//         console.log(error);
//         req.flash("errors",error)
//         return res.redirect("/api/login");
        
//     }
// }
export const getGoogleCallback = async (req, res) => {
    const { state, code } = req.query;
    const { google_oauth_state: storedStateInCookie, google_oauth_code_verifier: storedCodeVerifier } = req.cookies;
    
    // Validate the state and code
    if (!state || !code || !storedStateInCookie || !storedCodeVerifier || state !== storedStateInCookie) {
        req.flash("errors", "Invalid state");
        return res.redirect("/api/login");
    }

    let tokens;
    try {
        // Validate the authorization code
        tokens = await google.validateAuthorizationCode(code, storedCodeVerifier);
        const claims = decodeIdToken(tokens.idToken());
        

        const { sub: googleUserId, email, name } = claims;

        // 1. Check if OAuthAccount exists for the Google user
        let oauthAccount = await OAuthAccount.findOne({
            provider: "google",
            providerAccountId: googleUserId
        });
        let user;

        // 2. If OAuthAccount does not exist, create a new one
        if (!oauthAccount) {
            // Check if a user already exists with this email
             user = await User.findOne({ email }).select("-password");

            if (!user) {
                // If no user exists with this email, create a new user
                user = await User.create({ name, email, isEmail_Verified: true });
            }

            // Create a new OAuthAccount and link it to the user
            oauthAccount = await OAuthAccount.create({
                userId: user._id,
                provider: "google",
                providerAccountId: googleUserId
            });

            console.log("Created new OAuthAccount and linked to user:", user);
        } else {
            // If OAuthAccount exists, retrieve the linked user
            let user = await User.findById(oauthAccount.userId).select("-password");
            console.log("User already linked to OAuth account:", user);
        }

        // Generate the token and redirect the user to the home page
        generateToken(res, oauthAccount.userId);
        res.clearCookie("google_oauth_state");
        res.clearCookie("google_oauth_code_verifier");

        return res.redirect("/api/home");
    } catch (error) {
        console.log(error);
        req.flash("errors", error);
        return res.redirect("/api/login");
    }
};

