require('dotenv').config()
import { Response } from "express"
import { UserInterface } from "../models/user.model"
import { redis } from "./redis.config"

interface TokenOptionInterface {
    expires: Date
    maxAge: number
    httpOnly: boolean
    sameSite: 'lax' | 'strict' | 'none' | undefined
    secure?: boolean
}

 // parse envirement variable to in tegrates with fallback values

const accessTokenExpire = parseInt(process.env.ACCESS_TOKEN_EXPIRE || '300' , 10)
const refreshTokenExpire = parseInt(process.env.REFRESH_TOKEN_EXPIRE || '1200' , 10)

 // options for cookies

export const accessTokenOptions : TokenOptionInterface = {
    expires: new Date(Date.now() + accessTokenExpire * 60 * 60 * 1000),
    maxAge: accessTokenExpire*60*60* 1000,
    httpOnly: true,
    sameSite: 'lax'

}
export const refreshTokenOptions : TokenOptionInterface = {
    expires: new Date(Date.now() + refreshTokenExpire *24*60*60* 1000),
    maxAge: refreshTokenExpire *24*60*60* 1000,
    httpOnly: true,
    sameSite: 'lax'
}

export const sendToken =  (user: UserInterface, statusCode: number, res:Response) =>{
    const accessToken = user.signAccesToken()
    const refreshToken = user.signRefreshToken()


    // upload session to redis

    redis.set(user._id, JSON.stringify(user) as any)


    
    if(process.env.NODE_DEV ==='production'){
        accessTokenOptions.secure = true
        refreshTokenOptions.secure = true
    }

    res.cookie("access_token", accessToken, accessTokenOptions)
    res.cookie("refresh_token",refreshToken,refreshTokenOptions)
    res.status(statusCode).json({
        success: true,
        user,
        accessToken
    })
}
