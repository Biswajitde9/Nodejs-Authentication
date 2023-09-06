const express= require('express');
const expressLayouts = require('express-ejs-layouts');
const db = require('./config/mongoose');
const flash = require('connect-flash');
const session = require('express-session');
const passport = require('passport');

const app= express();
const port= 4000;

//passport configuration
require('./config/passport')(passport);

//EJS configuration...........................
app.use(expressLayouts);
//extract style and script from sub pages into the layout
app.set('layout extractStyles',true);
app.set('layout extractScripts',true);
app.use("/assets",express.static('./assets'));
app.set('view engine','ejs');

//Set up the view engine....................
app.set('views','./views');

//bodyparser configuration
app.use(express.urlencoded({ extended: false }))

//express session configuration
app.use(
    session({
        secret:'secret',
        resave: true,
        saveUninitialized: true
    })
);

//passport Middlewares.......................................
app.use(passport.initialize());
app.use(passport.session());

//connecting flash
app.use(flash());

//global variables
app.use(function(req,res,next){
    res.locals.success_msg= req.flash('success_msg'),
    res.locals.error_msg = req.flash('error_msg');
    res.locals.error = req.flash('error');
    next();
});

//set up routes..............................
app.use('/',require('./routes/index'));
app.use('/auth',require('./routes/auth'));

app.listen(port,(err)=>{
    if(err){
        console.log(`Server is giving an error,${err}`);
    }else{
        console.log(`Server is running successfully on port ${port}`);
    }
})

