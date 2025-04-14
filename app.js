import express from "express";
import dotenv from "dotenv"
import { connectToDb } from "./DB/connectToDb.js";
import userRouter from "./Routes/User.routes.js";
import cookieParser from "cookie-parser"
dotenv.config();
connectToDb();

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.set("view engine","ejs");
app.use(express.static("public"));
app.use("/api",userRouter);
app.listen(process.env.PORT,()=>console.log(`Server is running at http://localhost:${process.env.PORT}/api`));
