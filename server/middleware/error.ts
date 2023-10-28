import { Request,Response,NextFunction } from 'express'
import ErrorHandler from '../config/error.config'

export const ErrorMiddleware = (err:any, req:Request,res:Response, next:NextFunction)=>{
    err.statusCode =err.statusCode || 500
    err.message = err.message ||'internal server error'

    //wrong mongo id

    if(err.name ==='CastError'){
        const message = `ressource not found. Invalid ${err.path}`
        err= new ErrorHandler(message, 400)
    }

    // duplicated key 
    if(err.code ===11000){
        const message = `duplicated ${Object.keys(err.keyValue)} entred`
        err= new ErrorHandler(message, 400)
    }

    // jwt error
    if(err.name==='JsonWebTokenError'){
        const message = "invalid json web token"
        err= new ErrorHandler(message, 400)
    }
    // jwt expired
    if(err.name === 'TokenExpiredError'){
        const message = "Expired json web token "
        err= new ErrorHandler(message, 400)
    }

    res.status(err.statusCode).json({
        success: false,
        message:err.message
    })

}