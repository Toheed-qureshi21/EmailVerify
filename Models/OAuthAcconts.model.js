import mongoose from "mongoose";

const OAuthAccontsSchema = mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: "User",
    },
    provider:{
        type:String,
        enum:["google","github"],
        default:[],
    },
    providerAccountId:{
        type:String,
        // unique:true
    }
},{
    timestamps:true
});

export const OAuthAccount = mongoose.model("OAuthAccount",OAuthAccontsSchema);