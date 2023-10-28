import mongoose,{Document,Model,Schema} from "mongoose"
import bcrypt from 'bcryptjs'
const {isEmail} =require('validator')
require('dotenv').config()
import jwt from "jsonwebtoken"

export interface UserInterface extends Document {
    name:string;
    email: string;
    password: string;
    age:number;
    weight:number;
    height:number;
    avatar:{
        public_id: string;
        url: string;
    };
    role:string;
    isVerified: boolean;
    workout: Array<{workoutId: string}>
    steroidsCycle: Array<{cycleId: string}>
    meals: Array<{mealId: string}>
    comparePassword: (password: string) => Promise<boolean>
    signAccesToken: ()=> string
    signRefreshToken: ()=> string
}

const UserSchema: Schema<UserInterface> = new mongoose.Schema({
    name:{
        type:String,
        required: [true,"name is required" ]
    },
    email:{
        type:String,
        required: [true,"email is required"],
        unique: true,
        validate : [isEmail,"please enter a valid email"]
    },
    password:{
        type:String,
        required: [true, "password is required"],
        minlength:[6, "password must be at least 6 characters"]
    },
    age: { 
        type: Number ,
        min: [1, "You must be at least 1 year or older to register"],
        max: [150, "You must be at most 149 years to register"]
    },
    weight: { 
        type: Number ,
        min: [20, "You must be at least 20 kg or more"],
        max: [250, "You must be at most 249 kg to register"],
        default: 50
    },
    height: { 
        type: Number ,
        min: [100, "You must be at least 100 cm or more"],
        max: [300, "You must be at most 299 cm to register"],
        default: 150
    },
    avatar:{
        public_id:String,
        url:String
    },
    role:{
        type:String,
        default: "User"
    },
    isVerified:{
        type:Boolean,
        default: false
    },
    workout:[
        {
            workoutId:String
        }
    ],
    steroidsCycle:[
        {
            cycleId: String
        }
    ],
    meals:[
        {
            mealId: String
        }
    ]
},{timestamps:true})

//hash password
UserSchema.pre<UserInterface>('save',async function (next) {
    if(this.isModified('password')){
        this.password = await bcrypt.hash(this.password,10)
    }
    
    next()
})

//sign access token
UserSchema.methods.signAccesToken = function () {
    return jwt.sign({id: this._id},process.env.ACCESS_TOKEN || "",{expiresIn:'5m'})
}

//sign refresh token
UserSchema.methods.signRefreshToken = function () {
    return jwt.sign({id: this._id}, process.env.REFRESH_TOKEN || '',{expiresIn:'3d'})
}

//compare password
UserSchema.methods.comparePassword = async function (enteredPassword: string): Promise<boolean>{
    return await bcrypt.compare(enteredPassword, this.password)
}

const userModel: Model<UserInterface> = mongoose.model("user",UserSchema)
export default userModel
    
