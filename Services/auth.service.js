import { ForgotPassword } from "../Models/ForgotPassword.model.js";
import { User } from "../Models/User.model.js";
import { VerifyEmail } from "../Models/VerifyEmail.model.js";
import bcrypt from "bcryptjs"
import crypto from "crypto"

export const toHashPassword =async(password,salt) => {
   const hashedPassword = await bcrypt.hash(password,salt);
   return hashedPassword;
}
export const comparePassword = async(password,realPassword)=>{
    const isCompared = await bcrypt.compare(password,realPassword);
    return isCompared;
}
export const generateVerificationToken = (digit = 8) => {
    const min = 10 ** (digit - 1);
    const max = (10 ** digit) - 1;
    return crypto.randomInt(min, max).toString();
}
export const createVerifyEmailLink = (email, token) => {
    const uriEncodedEmail = encodeURIComponent(email);
    return `http://localhost:3000/api/verify-email-link?email=${uriEncodedEmail}&token=${token}`;
}

// findVerificationEmailToken
export const findVerificationEmailToken = async (token) => {
    const tokenData = await VerifyEmail.findOne({ token })
    if (!tokenData) {
        return null;
    }
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    if (tokenData.createdAt < twentyFourHoursAgo) {
        return null;
    }
    const userId = tokenData.userId;
    const user = await User.findOne({ _id: userId });
    if (!user) {
        return null;
    }

    return {
        ...tokenData._doc,
        email:user.email
    };

}
// verifyUserEmailAndUpdate
export const verifyUserEmailAndUpdate = async ({ email, userId }) => {
    const user = await User.findOneAndUpdate({ email }, { isEmail_Verified: true }, { new: true });
    
    await user.save();
    await VerifyEmail.deleteMany({userId});
    return user;
}


// ! Forgot password implementation

export const createResetPasswordLink = async ({userId}) => {
    const randomToken = crypto.randomBytes(32).toString("hex");
    const token_hash = crypto.createHash("sha256").update(randomToken).digest("hex");  // 64 characters
    await ForgotPassword.deleteMany({userId});
    await ForgotPassword.insertOne({
        userId,
        token_hash,
        createdAt: new Date(),
    });

    return `http://localhost:3000/api/reset-password/${randomToken}`;
}

export const getResetPasswordData = async(token) => {
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    const data = await ForgotPassword.findOne({token_hash:tokenHash});
    return data;
}

export const updatePassword = async(userId,newPassword,salt=12) => {
    const newHashedPassword = await toHashPassword(newPassword,salt);
    await User.updateOne(
        { _id: userId },
        { $set: { password: newHashedPassword } }
    );
}