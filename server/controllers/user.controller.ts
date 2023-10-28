import { Request, Response, NextFunction, response } from "express"
import userModel, { UserInterface } from "../models/user.model"
import ErrorHandler from "../config/error.config"
import { CatchAsyncErrors } from "../middleware/asyncErrors"
import jwt, { JwtPayload, Secret } from "jsonwebtoken"
require('dotenv').config()
import ejs from 'ejs'
import path from 'path'
import sendMail from "../config/mail.config"
import {accessTokenOptions, refreshTokenOptions, sendToken} from "../config/jwt.config"
import { redis } from "../config/redis.config"
import cloudinary from "cloudinary"
// register interface

interface RegisterInterface{
    name:string
    email:string
    password:string
}

export const registerUser = CatchAsyncErrors(async(req:Request,res:Response, next:NextFunction)=>{
    try{
        const {name,email,password} =req.body
        const isEmailExist = await userModel.findOne({email})
        if(isEmailExist){
            return next(new ErrorHandler("email already exist", 400))
        }
        const user : RegisterInterface ={
            name,
            email,
            password,
        }
        const activationToken = createActivationToken(user)
        const activationCode= activationToken.activationCode

        const data = {user: {name:user.name}, activationCode}
        const html = await ejs. renderFile(path.join(__dirname,"../mails/activation-mail.ejs"),data)
        try{
            await sendMail({
                email: user.email,
                subject: "Activate your account",
                template: "activation-mail.ejs",
                data
            })
            res.status(201).json({
                success: true,
                message: `please check your email ${user.email} to activate your account`,
                activationToken: activationToken.token
            })
        }catch(err:any){
            return next(new ErrorHandler(err.message,400))
        }
    }catch(err:any){
        return next(new ErrorHandler(err.message,400))
    }
})

// token interface
interface ActivationTokenInterface{
    token:string
    activationCode:string
}

// token function 
export const createActivationToken= (user: RegisterInterface): ActivationTokenInterface =>{
    const activationCode = Math.floor(1000 + Math.random()*9000).toString()
    
    const token = jwt.sign(
        {
            user,
            activationCode
        },
        process.env.ACTIVATION_SECRET as Secret,
        {
            expiresIn:"5m"
        }
    )
    return {token, activationCode}
}

// activate user 
interface ActivationRequestInterface{
    activation_token:string
    activation_code: string
}

export const activateUser = CatchAsyncErrors(async(req:Request,res:Response,next:NextFunction)=>{
    try{
        const {activation_token, activation_code} = req.body as ActivationRequestInterface
        const newUser: {user:UserInterface; activationCode:string}= jwt.verify(
            activation_token,
            process.env.ACTIVATION_SECRET as string
        ) as {user: UserInterface; activationCode:string}
        if(newUser.activationCode !== activation_code){
            return next(new ErrorHandler("Invalid activation code",400))
        }
        const {name,email,password} = newUser.user
        const existUser = await userModel.findOne({email})
        if(existUser){
            return next(new ErrorHandler("email already exist", 400))
        }
        const user = await userModel.create({
            name,
            email,
            password
        })

        res.status(201).json({
            success:true,
            message: `${user.email} account is activated`
        })
    }catch(err:any){
        return next(new ErrorHandler(err.message, 400))
    }
})

// login

interface LoginInterface {
    email: string
    password: string
}

export const loginUser = CatchAsyncErrors(async(req:Request,res:Response,next:NextFunction)=>{
    try{
        const {email, password} =req.body as LoginInterface
        if(!email || !password){
            return next(new ErrorHandler("Please enter both email and password", 400))
        }
        const user = await userModel.findOne({email})
        if(!user){
            return next(new ErrorHandler("invalid email or password",400))
        }

      
       
        const isCorrectPassword= await user.comparePassword(password)
        if(!isCorrectPassword){
            return next(new ErrorHandler("invalid email or password", 400))
        }
        sendToken(user, 200, res)
        
    }catch(err:any){
        return next(new ErrorHandler(err.message, 400))
    }
})



export const  logoutUser = CatchAsyncErrors(async(req:Request, res: Response, next:NextFunction)=>{
    try{
        res.cookie("access_token","",{maxAge: 1})
        res.cookie("refresh_token","",{maxAge: 1})
        const userId = req.body.user._id || ""
        redis.del(userId)
        res.status(200).json({
            success: true,
            message: "user logged out"
        })
    }catch(err:any){
        return next(new ErrorHandler(err.message, 400))
    }
})

// update access token

export const  updateAccessToken = CatchAsyncErrors(async(req:Request,res:Response,next:NextFunction)=>{
    try{
        const refresh_token = req.cookies.refresh_token as string
        const decoded = jwt.verify(refresh_token, process.env.REFRESH_TOKEN as string) as JwtPayload

        const message = 'Could not refresh token'

        if(!decoded){
            return next(new ErrorHandler(message,400))
        }
        const session = await redis.get(decoded.id as string)

        if(!session){
            return next(new ErrorHandler(message, 400))
        }

        const user = JSON.parse(session)
        const accessToken= jwt.sign({id:user._id},process.env.ACCESS_TOKEN as string,{expiresIn:"5m"})
        const refreshToken= jwt.sign({id:user._id},process.env.REFRESH_TOKEN as string,{expiresIn:"3d"})
        req.body.user = user
        res.cookie('access_token',accessToken,accessTokenOptions)
        res.cookie('refresh_token',refreshToken,refreshTokenOptions)
        res.status(200).json({
            success:true,
            accessToken
        })
    }catch(err:any){
        return next(new ErrorHandler(err.message, 400))
    }
})

// get user

export const getUser = CatchAsyncErrors(async(req:Request,res:Response,next:NextFunction)=>{
    try{
        const user = await userModel.findById(req.body.user._id)
        res.status(201).json({
            success:true,
            user
        })
    }catch(err:any){
        return next(new ErrorHandler(err.message, 400))
    }
})

interface SocialAuthInterface {
    email: string
    name:string
    avatar:string
}

//social auth
export const socialAuth = CatchAsyncErrors(async (req:Request, res: Response, next:NextFunction)=>{
    try{
        const {email, name, avatar} = req.body as SocialAuthInterface
        const user = await userModel.findOne({email})
        if(!user){
            const newUser = await userModel.create({email,name,avatar})
            sendToken(newUser, 200, res)
        }else{
            sendToken(user, 200, res)
        }
    }catch(err:any){
        return next(new ErrorHandler(err.message, 400))
    }
})

// update user 
interface UpdateUserInterface {
    name?:string
    email?:string
}


export const updateUserInfo = CatchAsyncErrors(async(req:Request, res:Response, next:NextFunction)=>{
    try{
        const {name,email} = req.body as UpdateUserInterface
        const userId = req.body.user._id
        const userJson = await redis.get(userId) 
        if(userJson){
            const user = JSON.parse(userJson)
            if(email && user){
                const isEmailExist = await userModel.findOne({email})
                if(isEmailExist){
                    return next (new ErrorHandler("email already exisit",400))
                }
                user.email = email
            }
    
            if(name && user){
                user.name = name
            }

           
          
    
            await userModel.findOneAndUpdate(
                {_id: userId},
                user,
                { new: true, runValidators: true }
            )
    
            await redis.set(userId, JSON.stringify(user))
    
            res.status(201).json({
                success: true,
                user
            })
        }
        
    }catch(err:any){
        return next(new ErrorHandler(err.message, 400))
    }
})

// update user password
interface UpdatePassInterface {
    oldPassword:string
    newPassword:string
}

export const  updatePassword = CatchAsyncErrors(async(req:Request,res: Response, next:NextFunction)=>{
    try{
        const {oldPassword, newPassword} = req.body as UpdatePassInterface
        if(!oldPassword || !newPassword){
            return next(new ErrorHandler("please enter old and new password",400))
        }
        const user = await userModel.findById(req.body.user._id)
        if(!user?.password){
            return next( new ErrorHandler("invalid user", 400))
        }

        const isCorrectPassword = await user.comparePassword(oldPassword)
        if(!isCorrectPassword){
            return next( new ErrorHandler("password incorrect",400))
        } 
        user.password =newPassword 

        await user.save()
        await redis.set(user._id, JSON.stringify(user))
            res.status(201).json({
            success: true,
            user
            })
    
        
    }catch(err:any){
        return next(new ErrorHandler(err.message, 400))
    }
})

// update avatar
interface AvatarInterface {
    avatar: string
}

export const  updateAvatar = CatchAsyncErrors(async(req:Request,res:Response,next:NextFunction)=>{
    try{
        const {avatar} = req.body as AvatarInterface
        const userId =req.body.user
        const user = await userModel.findById(userId)
        if(!user){
            return next(new ErrorHandler("invalid user",400))
        }
        if(avatar ){
            if(user.avatar.public_id){
                await cloudinary.v2.uploader.destroy(user.avatar.public_id)
            }
            const newAvatr=await cloudinary.v2.uploader.upload(avatar,{
                folder:"avatars",
                width: 150
            })
            user.avatar= {
                public_id: newAvatr.public_id,
                url: newAvatr.secure_url
            }
            await user.save()
            await redis.set(user._id, JSON.stringify(user))
            res.status(201).json({
                    success: true,
                    user
            })
        }
    }catch(err:any){
        return next(new ErrorHandler(err.message, 400))
    }
})
