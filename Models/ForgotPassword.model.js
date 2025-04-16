import mongoose from "mongoose";

const forgotPasswordSchema = mongoose.Schema({
    userId:{
        type:mongoose.Schema.Types.ObjectId,
        required:true,
        unique:true,
        ref:"User"
    },
    token_hash:{
        type:String,
        unique:true,
        required:true
    },
    createdAt:{
        type:Date,
        required:true,
        default:Date.now,
        expires:60*60*1000
    },
},{
    timestamps:true
});

export const ForgotPassword = mongoose.model("ForgotPassword",forgotPasswordSchema);