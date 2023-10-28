import { Request, Response, NextFunction } from "express"
import { CatchAsyncErrors } from "./asyncErrors"
import ErrorHandler from "../config/error.config"
import jwt, { JwtPayload } from "jsonwebtoken"
require('dotenv').config()
import { redis } from "../config/redis.config"
import { UserInterface } from "../models/user.model"




export const isAuthenticated = CatchAsyncErrors(async(req:Request,res:Response,next:NextFunction)=>{
    const access_token = req.cookies.access_token as string
    if(!access_token){
        return next(new ErrorHandler("please login to access this ressource ", 400))
    }
    const decoded = jwt.verify(access_token, process.env.ACCESS_TOKEN as string) as JwtPayload
    if(!decoded){
        return next (new ErrorHandler("access token is not valid",400))
    }
    const user = await redis.get(decoded.id)
    if(!user){
        return next(new ErrorHandler('user not found',400))
    }
    req.body.user= JSON.parse(user)
    next()
})


// validate role

export const authRoles = (...roles: String[]) =>{
    return (req:Request, res:Response, next:NextFunction)=>{
        
        if(!roles.includes(req.body.user.role || '')){
            return next( new ErrorHandler(`Role ${req.body.user.role} is not allowed to access this resource`,403))
        }
        next()
    }
}