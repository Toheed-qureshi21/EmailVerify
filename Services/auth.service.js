import { User } from "../Models/User.model.js";
import { VerifyEmail } from "../Models/VerifyEmail.model.js";
import crypto from "crypto"

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
// clearVerifyEmailTokens
