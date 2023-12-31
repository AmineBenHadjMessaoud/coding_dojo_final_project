require('dotenv').config()
import express, { Request,Response,NextFunction } from "express"
export const app= express()
import cors from "cors"
import cookieParser from "cookie-parser"
import {ErrorMiddleware} from "./middleware/error"
import userRouter from "./routes/user.route"

app.use(express.json(), express.urlencoded({ extended: true }))

app.use(cookieParser())

app.use(cors({origin:process.env.ORIGIN}))

//routes
app.use("/api",userRouter)

app.get("/test", (req:Request,res:Response, next:NextFunction)=>{
    res.status(200).json({
        success: true,
        message:"api is working",
    })
})

app.all("*",(req: Request, res:Response, next: NextFunction)=>{
    const err = new Error(`Route ${req.originalUrl} not found`) as any
    err.statusCode= 404
    next(err)
    
})

app.use(ErrorMiddleware)