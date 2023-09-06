const passport = require('passport');
const bcryptjs= require('bcryptjs');
const nodemailer = require('nodemailer');
const { google } = require('googleapis');
const OAuth2 = google.auth.OAuth2;
const jwt = require('jsonwebtoken');
const JWT_KEY = "jwtactive987";
const JWT_RESET_KEY = "jwtreset987";

// import user model.................
const User = require('../models/User');

// Register form Handle................
exports.registerHandle = async (req, res) => {
    const { name, email, password, password2 } = req.body;
    let errors = [];
    
    // Checking required field...............
    if (!name || !email || !password || !password2) {
      errors.push({ msg: 'Please enter all fields' });
    }
    
    // Checking password mismatch....................
    if (password !== password2) {
      errors.push({ msg: 'Passwords do not match' });
    }
    
    // Checking password length......................
    if (password.length < 8) {
      errors.push({ msg: 'Password must be at least 8 characters' });
    }
  
    if (errors.length > 0) {
      res.render('register', {
        errors,
        name,
        email,
        password,
        password2,
      });
    } else {
      try {
        // Validation passed..................
        const user = await User.findOne({ email: email });
  
        if (user) {
          // If user already exists
          errors.push({ msg: 'Email already exists' });
          res.render('register', {
            errors,
            name,
            email,
            password,
            password2,
          });
        } else {
          // Set up the OAuth2 client and get the access token
          const oauth2Client = new OAuth2(
            "920745956561-t8s7j9ulj79bidbt2f8jl0u0mc4pni2d.apps.googleusercontent.com",
            "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",
            "https://developers.google.com/oauthplayground"
          );
  
          oauth2Client.setCredentials({
            refresh_token: "1//040XLioOw7mThCgYIARAAGAQSNwF-L9Ir3p0pKG6DYaHBxvKva9HWDZ8caIWg6_aOba36zVqkBPayXODgxWRK26Ad6ZkHSPWLOq8",
          });
          
          const accessToken = oauth2Client.getAccessToken();
          const token = jwt.sign({ name, email, password }, JWT_KEY, { expiresIn: '30m' });
          const CLIENT_URL = 'http://' + req.headers.host;
          const output = `
            <h2>Hi ${name},</h2>
            <p>Thank you for registering with our service.</p>
            <p>Please click on the following link to activate your account:</p>
            <a href="${CLIENT_URL}/auth/activate/${token}">Activate Account</a>
            <p><b>NOTE:</b> The activation link expires in 30 minutes.</p>
            <p>If you didn't sign up for our service, please ignore this email.</p>
            <p>Best regards,</p>
            <p>The Node js Auth(Biswajit)</p>
          `;
  
          const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
              type: "OAuth2",
              user: "biswajitde487@gmail.com",
              clientId: "920745956561-t8s7j9ulj79bidbt2f8jl0u0mc4pni2d.apps.googleusercontent.com",
              clientSecret: "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",
              refreshToken: "1//040XLioOw7mThCgYIARAAGAQSNwF-L9Ir3p0pKG6DYaHBxvKva9HWDZ8caIWg6_aOba36zVqkBPayXODgxWRK26Ad6ZkHSPWLOq8",
              accessToken: accessToken
            },
          });
  
          // Send mail with defined transport object
          const mailOptions = {
            from: '"NodeJS Auth" <biswajitde487@gmail.com>',
            to: email,
            subject: "Account Verification",
            generateTextFromHTML: true,
            html: output,
          };
  
          await transporter.sendMail(mailOptions);
          console.log('Mail sent');
          
          req.flash(
            'success_msg',
            'Activation link sent to email ID. Please activate to log in.'
          );
          res.redirect('/auth/login');
        }
      } catch (error) {
        console.error(error);
        req.flash(
          'error_msg',
          'Something went wrong on our end. Please register again.'
        );
        res.redirect('/auth/login');
      }
    }
  };
  

//------------ Activate Account Handle ------------//
exports.activateHandle = async (req, res) => {
    const token = req.params.token;
    let errors = [];
    
    if (token) {
      try {
        const decodedToken = jwt.verify(token, JWT_KEY);
        const { name, email, password } = decodedToken;
  
        const user = await User.findOne({ email: email });
  
        if (user) {
          // User already exists
          req.flash(
            'error_msg',
            'Email ID already registered! Please log in.'
          );
          res.redirect('/auth/login');
        } else {
          const newUser = new User({
            name,
            email,
            password,
          });
  
          const salt = await bcryptjs.genSalt(10);
          newUser.password = await bcryptjs.hash(newUser.password, salt);
  
          await newUser.save();
  
          req.flash(
            'success_msg',
            'Account activated. You can now log in.'
          );
          res.redirect('/auth/login');
        }
      } catch (err) {
        req.flash(
          'error_msg',
          'Incorrect or expired link! Please register again.'
        );
        res.redirect('/auth/register');
      }
    } else {
      console.log('Account activation error!');
    }
  };
  

//------------ Forgot Password Handle ------------//
exports.forgotPassword = async (req, res) => {
    const { email } = req.body;
    let errors = [];
  
    // Checking required fields
    if (!email) {
      errors.push({ msg: 'Please enter an email ID' });
    }
  
    if (errors.length > 0) {
      res.render('forgot', {
        errors,
        email,
      });
    } else {
      try {
        const user = await User.findOne({ email: email });
  
        if (!user) {
          // User does not exist
          errors.push({ msg: 'User with Email ID does not exist!' });
          res.render('forgot', {
            errors,
            email,
          });
        } else {
          // Set up the OAuth2 client and get the access token
          const oauth2Client = new OAuth2(
            "920745956561-t8s7j9ulj79bidbt2f8jl0u0mc4pni2d.apps.googleusercontent.com",
            "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",
            "https://developers.google.com/oauthplayground"
          );
  
          oauth2Client.setCredentials({
            refresh_token: "1//040XLioOw7mThCgYIARAAGAQSNwF-L9Ir3p0pKG6DYaHBxvKva9HWDZ8caIWg6_aOba36zVqkBPayXODgxWRK26Ad6ZkHSPWLOq8",
          });
  
          const accessToken = oauth2Client.getAccessToken();
          const token = jwt.sign({ _id: user._id }, JWT_RESET_KEY, { expiresIn: '30m' });
          const CLIENT_URL = 'http://' + req.headers.host;
          const output = `
          <h2>Hi ${user.name},</h2>
          <p>We received a request to reset your account password.</p>
          <p>Please click on the following link to reset your password:</p>
          <a href="${CLIENT_URL}/auth/forgot/${token}">Reset Password</a>
          <p><b>NOTE:</b> The reset link expires in 30 minutes.</p>
          <p>If you didn't request this password reset, please ignore this email.</p>
          <p>Best regards,</p>
          <p>The Node Js Auth</p>
          `;
  
          await User.updateOne({ resetLink: token });
  
          const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
              type: "OAuth2",
              user: "biswajitde487@gmail.com",
              clientId: "920745956561-t8s7j9ulj79bidbt2f8jl0u0mc4pni2d.apps.googleusercontent.com",
              clientSecret: "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",
              refreshToken: "1//040XLioOw7mThCgYIARAAGAQSNwF-L9Ir3p0pKG6DYaHBxvKva9HWDZ8caIWg6_aOba36zVqkBPayXODgxWRK26Ad6ZkHSPWLOq8",
              accessToken: accessToken
            },
          });
  
          // Send mail with defined transport object
          const mailOptions = {
            from: '"Node js Auth" <biswajitde487@gmail.com>', // sender address
            to: email, // list of receivers
            subject: "Account Password Reset", // Subject line
            html: output, // html body
          };
  
          const info = await transporter.sendMail(mailOptions);
          console.log('Mail sent:', info.response);
  
          req.flash(
            'success_msg',
            'Password reset link sent to email ID. Please follow the instructions.'
          );
          res.redirect('/auth/login');
        }
      } catch (error) {
        console.error(error);
        req.flash(
          'error_msg',
          'Something went wrong on our end. Please try again later.'
        );
        res.redirect('/auth/forgot');
      }
    }
  };
  
            
            //------------ Redirect to Reset Handle ------------//
exports.gotoReset = async (req, res) => {
                const { token } = req.params;
              
                if (token) {
                  try {
                    const decodedToken = await jwt.verify(token, JWT_RESET_KEY);
                    const { _id } = decodedToken;
              
                    const user = await User.findById(_id);
              
                    if (!user) {
                      req.flash(
                        'error_msg',
                        'User with email ID does not exist! Please try again.'
                      );
                      res.redirect('/auth/login');
                    } else {
                      res.redirect(`/auth/reset/${_id}`);
                    }
                  } catch (err) {
                    req.flash(
                      'error_msg',
                      'Incorrect or expired link! Please try again.'
                    );
                    res.redirect('/auth/login');
                  }
                } else {
                  console.log("Password reset error!");
                }
              };
              


exports.resetPassword = async (req, res) => {
    const { password, password2 } = req.body;
                        const id = req.params.id;
                        let errors = [];
                    
                        try {
                        // Checking required fields
                        if (!password || !password2) {
                            req.flash(
                            'error_msg',
                            'Please enter all fields.'
                            );
                            return res.redirect(`/auth/reset/${id}`);
                        }
                    
                        // Checking password length
                        if (password.length < 8) {
                            req.flash(
                            'error_msg',
                            'Password must be at least 8 characters.'
                            );
                            return res.redirect(`/auth/reset/${id}`);
                        }
                    
                        // Checking password mismatch
                        if (password !== password2) {
                            req.flash(
                            'error_msg',
                            'Passwords do not match.'
                            );
                            return res.redirect(`/auth/reset/${id}`);
                        }
                    
                        const salt = await bcryptjs.genSalt(10);
                        const hash = await bcryptjs.hash(password, salt);
                    
                        await User.findByIdAndUpdate(
                            id,
                            { password: hash },
                        );
                    
                        req.flash(
                            'success_msg',
                            'Password reset successfully!'
                        );
                        res.redirect('/auth/login');
                        } catch (error) {
                        console.error(error);
                        req.flash(
                            'error_msg',
                            'Error resetting password!'
                        );
                        res.redirect(`/auth/reset/${id}`);
                        }
                    };
                    

//------------ Login Handle ------------//
exports.loginHandle = (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/auth/login',
        failureFlash: true
    })(req, res, next);
}

//------------ Logout Handle ------------//
exports.logoutHandle = (req, res) => {
    req.logout(function(err){
        if(err){
            console.error(err);
        }
    req.flash('success_msg', 'You are logged out');
    res.redirect('/auth/login');
    });
}
