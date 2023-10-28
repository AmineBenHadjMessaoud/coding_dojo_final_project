import express from 'express'
import { activateUser, registerUser,loginUser, logoutUser, updateAccessToken, getUser, socialAuth, updateUserInfo, updatePassword, updateAvatar } from '../controllers/user.controller'
import { authRoles, isAuthenticated } from '../middleware/authorization'
const userRouter = express.Router()



userRouter.post('/registration',registerUser)
userRouter.post('/activate-user',activateUser)
userRouter.post('/login', loginUser)
userRouter.get('/logout',isAuthenticated,authRoles("admin"), logoutUser)
userRouter.get('/refresh',updateAccessToken)
userRouter.get('/user-info',isAuthenticated,getUser)
userRouter.post("/social-auth", socialAuth)
userRouter.put("/update-user-info", isAuthenticated,  updateUserInfo)
userRouter.put("/update-password", isAuthenticated,updatePassword)
userRouter.put("/update-avatar", isAuthenticated,updateAvatar)

export default userRouter