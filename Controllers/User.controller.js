import fs from "fs/promises";
import path from "path"
import ejs from "ejs"
import bcrypt from "bcryptjs"
import { User } from "../Models/User.model.js"
import { generateToken } from "../Utils/generateToken.js";
import { VerifyEmail } from "../Models/VerifyEmail.model.js";

// import { sendEmail } from "../Libs/nodemailer.js";
import { sendEmail } from "../Libs/resend.js";
import { comparePassword, createVerifyEmailLink, findVerificationEmailToken, generateVerificationToken, toHashPassword, verifyUserEmailAndUpdate } from "../Services/auth.service.js";
import mjml2html from "mjml";
import { password } from "bun";
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
        const hashedPassword = await toHashPassword(password,12)
        const user = await User.create({
            name, 
            email,
            password: hashedPassword 
        });
        generateToken(res, user._id);
        res.redirect("/api/home");
        return res.status(201).json({ message: "User created successfully" });

    } catch (error) {
        console.log(error);
        return res.status(500).json({ error: "Internal server error" });

    }
}
export const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: "All fields are required" });
        }
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: "User not found" });
        }
        const isPasswordMatch =await comparePassword(password, user.password);
        if (!isPasswordMatch) {
            return res.status(400).json({ error: "Invalid credentials" });
        }
        generateToken(res, user._id);
        res.redirect("/api/home");
        return res.status(200).json({ message: "Login successful" });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ error: "Internal server error" });
    }
}

export const logout = async (req, res) => {
    try {
        res.clearCookie("token");
        res.clearCookie("isLoggedIn");
        return res.redirect("/api/login");
    } catch (error) {
        return res.status(500).json({ error: "Internal server error" });
    }

}

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
        const mjmlTemplate = await fs.readFile(path.join(import.meta.dirname,"../emails/verify-email.mjml"), "utf-8");
        // ! Step 2:- To replace placeholder in .mjml file with actual values of links and randomToken
        const filledMjmlTemplate = ejs.render(mjmlTemplate, {
            code: randomToken,
            link:verifyEmailLink
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

export const toChangePassword = async (req,res) => {
    const {currentPassword,newPassword,confirmPassword} = req.body;
    if (!currentPassword || !newPassword || !confirmPassword) {
        req.flash("errors","All fields are required");
        return res.redirect("/api/change-password");
    }
    if (newPassword !== confirmPassword) {
        req.flash("errors","New password and confirm password does not match");
        return res.redirect("/api/change-password");
    }
    const userId = req.user._id.toString()
    const user = await User.findOne({_id:userId});
    if (!user) {
        req.flash("errors","User not found")
        return res.redirect("/api/change-password")
    }

    const isPasswordMatch = await comparePassword(currentPassword,user.password);
    if (!isPasswordMatch) {
        req.flash("errors","Current password does not match")
        return res.redirect("/api/change-password")
    }
    const newHashedPassword =await toHashPassword(newPassword,12);
    await User.updateOne(
        {_id:userId},
        {$set:{password:newHashedPassword}}
    );
    req.flash("success_msg","Password Updated Successfully");
    return res.redirect("/api/home");
    
}