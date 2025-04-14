import mongoose from "mongoose"
import {config} from "dotenv"
config();
export const connectToDb = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI,{
            dbName:"EmailVerify"
        });
        console.log("Mongodb connected ✅");
    } catch (error) {
        console.log("Error in mongodb connection",error);
    }
}