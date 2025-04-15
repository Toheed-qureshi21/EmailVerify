import jwt from "jsonwebtoken";
import { User } from "../Models/User.model.js";
export const isAuthenticate = async(req, res, next) => {
    try {
        const token = req.cookies.token;
        
        if(!token){
            return res.status(401).json({error:"Unauthorized please login"});
        }
        const userId = jwt.verify(token,process.env.JWT_SECRET);
        const user = await User.findById(userId.id);
        if(!user){
            return res.status(401).json({error:"Unauthorized please login"});
        }
        req.user = user;
        next();
    } catch (error) {
        console.log(error);
        return res.status(500).json({error:"Internal server error"});
        
    }
}
export const checkIfUserLoggedIn = (req,res,next) => {
    const isLoggedIn= req?.cookies?.isLoggedIn;
    if (isLoggedIn) {
     res.redirect("/api/home")
    }
    next();
}