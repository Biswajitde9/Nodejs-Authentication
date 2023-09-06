const express = require('express');
const router = express.Router();
//Importing Controllers
const controllers = require('../controllers/controllers');


//login routes..................................
router.get('/login',(req,res) =>
    res.render('login')
);

//Forgot password routes....................................
router.get('/forgot',(req,res) => res.render('forgot'));

//reset password routes.............................
router.get('/reset/:id',(req,res)=>{
    res.render('reset', { id: req.params.id})
});

//Register route.......................................................
router.get('/register',(req,res)=> 
    res.render('register')
);
//register POST handle..........................................................
router.post('/register',controllers.registerHandle);
//email activation...........................
router.get('/activate/:token',controllers.activateHandle);

//forgot password handle...........................................


//reset password handle...................
router.post('/reset/:id',controllers.resetPassword);

//reset password handle................................
router.get('/forgot/:token',controllers.gotoReset);
router.post('/forgot',controllers.forgotPassword);
//Login POST handle.....................
router.post('/login',controllers.loginHandle);

//logout GET handle..........................
router.get('/logout',controllers.logoutHandle);

module.exports=router;
