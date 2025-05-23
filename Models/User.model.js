import mongoose from "mongoose";

const userSchema = mongoose.Schema({
    name:{
        type:String,
        required:true
    },
    email:{
        type:String,
        required:true,
        unique:true
    },
    password:{
        type:String,
    },
    isEmail_Verified:{
        type:Boolean,
        required:true,
        default:false
    }
},{
    timestamps:true
});

export const User = mongoose.model("User",userSchema);