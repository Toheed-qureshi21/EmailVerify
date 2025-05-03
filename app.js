import express from "express";
import dotenv from "dotenv"
import cookieParser from "cookie-parser"
import session from "express-session";
import flash from "connect-flash";
import { connectToDb } from "./DB/connectToDb.js";
import userRouter from "./Routes/User.routes.js";

dotenv.config();
connectToDb();

const app = express();
app.use(session({
    secret:process.env.SESSIOIN_SECRET_KEY,
    resave:false,
    saveUninitialized:true,
    cookie: {
        httpOnly: true,
        secure: false, // Set to true if you're using HTTPS
        maxAge: 1000 * 60 * 60, // 1 hour
      },
}));
app.set("view engine","ejs");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(flash())
app.use(cookieParser());

app.use(express.static("public"));
app.use("/api",userRouter);
app.listen(process.env.PORT,()=>console.log(`Server is running at http://localhost:${process.env.PORT}/api`));
