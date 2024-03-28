const jwt=require("jsonwebtoken");
require("dotenv").config();
const cookies = require("cookie-parser");
exports.auth=(req,res,next)=>{
    try{
        const token = req.cookies.token || req.body.token || req.header("Authorization").replace("Bearer ","");
        
        if(!token || token==undefined){
            return res.status(401).json({
                success:false,
                message:'Token Missing',
            });
        }

        try{
            const payload=jwt.verify(token,process.env.JWT_SECRET);
            console.log(payload);

            req.user = payload;
        }catch(error){
            return res.status(401).json({
                success:false,
                message:"Token is Invalid",
            });
        }

        next();
    }catch(error){
        res.status(401).json({
            success:false,
            message:"Something went wrong, while verifying token",
        });
    }
}

exports.isStudent = (req,res,next)=>{
    try{
        if(req.user.role != "Student"){
            return res.status(401).json({
                success:false,
                message:"This is a protected route for students",
            });
        }

        next();
    }catch(error){
        return res.status(500).json({
            success:false,
            message:"User role is not matching",
        });
    }
}

exports.isAdmin = (req,res,next)=>{
    try{
        if(req.user.role != "Admin"){
            return res.status(401).json({
                success:false,
                message:"This is a protected route for Admins",
            });
        }

        next();
    }catch(error){
        return res.status(500).json({
            success:false,
            message:"User role is not matching",
        });
    }
}