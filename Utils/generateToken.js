import jwt from "jsonwebtoken"

export const generateToken =(res,id) => {
     const token = jwt.sign({id},process.env.JWT_SECRET,{expiresIn:"7d"});
      res.cookie("token",token,{httpOnly:true,sameSite:"Lax",secure:false,maxAge:7*24*60*60*1000});
      res.cookie("isLoggedIn",true,{httpOnly:true,sameSite:"Lax",secure:false,maxAge:7*24*60*60*1000});
}
