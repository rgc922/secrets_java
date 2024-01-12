//jshint esversion:6

// const express = require("express");
// const body = require("body-parser");
// const ejs = require("ejs");
// const pg = require("pg");



import express from "express";
import body from "body-parser";
import ejs from "ejs";
import pg from "pg";
import bcrypt from "bcrypt"; 

import dotenv from "dotenv";

import session from "express-session";

import passport from "passport";

import LocalStrategy from "passport-local";

import {Sequelize, DataTypes} from "sequelize";

import flash from "connect-flash";

import { Strategy as GoogleStrategy} from "passport-google-oauth20";

import FacebookStrategy from "passport-facebook";

// const mongoose = require("mongoose");

// COn PostGres y no con mongoo
// https://github.com/IMRS1311/Authentication-Levels-With-Postgres/blob/main/mySecret.js
// https://github.com/IMRS1311/Authentication-Levels-With-Postgres

// How to user Bcrypt DotEnv Sequelizr
// https://medium.com/@rachealkuranchie/node-js-authentication-with-postgresql-sequelize-and-express-js-20ae773da4c9
 
const app = express();
 
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(body.urlencoded({ extended: true }));


dotenv.config();

// console.log(process.env);
// console.log(process.env.PasswordDB);
const passwordDB = process.env.PasswordDB;
const saltRounds = process.env.SaltRounds; 
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;

const FACEAPPID = process.env.FACEAPPID;

const FACESECRET = process.env.FACESECRET;


// SESSION It's also used by flash
app.use(session({
  secret: "Our little Secret.",
  resave: false,
  saveUninitialized: false
}));

app.set('view engine', 'ejs');

app.use(flash());


app.use(passport.initialize());
app.use(passport.session());

// New connection using sequelize

const sequelize = new Sequelize('authentication', 'postgres', passwordDB, {
  host: 'localhost',
  dialect: 'postgres',
  define: {
    freezeTableName: true
  }
}

);

// Check connection
// try {
//   await sequelize.authenticate();
//   console.log('Connection has been established successfully.');
// } catch (error) {
//   console.error('Unable to connect to the database:', error);
// }

const User = sequelize.define('auth2', {
  // Model attributes are defined here
  username: {
    type: DataTypes.STRING,
    // allowNull: false
  },
  password: {
    type: DataTypes.STRING,
    // allowNull: false
  },
  googleid: {
    type: DataTypes.STRING,
  }
  ,
  facebookid: {
    type: DataTypes.STRING,
  }
}, {
  timestamps: false // by default User have date and time but my table doesn't have those

});

// console.log(User === sequelize.models.auth2); // true

passport.use(new LocalStrategy( 
  
  // {
  //   usernameField: "username",
  //   passwordField: "password"
  // },

  async function verify(username, password, done){

  try {
    // Find User
    const user = await User.findOne({ where: {username: username}});

    if (!user) {
      return done(null, false, { message: "The user name is not correct, try again"});
    }

    // Compare the password provided

    const checkPass = await bcrypt.compare(password, user.password);

    if (!checkPass) {
      return done(null, false, { message: "The password is not correct, try again!"})
    }

    return done(null, user);

  } catch (err) {
    return done(err);
  }

}));



passport.serializeUser(function(user, done) {
  done(null, user.id);
});


passport.deserializeUser((id, done) => {
    User.findByPk(id).then(user => {
        if (user) {
            done(null, user);
        } else {
            done(null, false); // or handle invalid user
        }
    }).catch(error => {
        done(error, null);
    });
});

//  

passport.use(new GoogleStrategy({
  clientID: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
  state: true
  },
  async function verify(accessToken, refreshToken, profile, done) {

    // console.log(profile);

    try {

      const user = await User.findOne( { where: { googleid : profile.id } });
      // console.log("USER NULL ????", user);
      if (!user) {
        // console.log("segunto try");
        try {
          const user = await User.create({
            googleid: profile.id,
            username: profile.emails[0].value          
            });
          console.log("User created ",user);
          return done(null, user);
        } catch (err) {
          console.log(err);
          return done(err, user);
        }
      } else {
        return done(null, user);
      }


    } catch (err) {
      console.log(err);
      return done(err);
    }

  // //id: '110269538995256656990' este es el de guardar profile.id 
  // //displayName name: {familyName: "Brewery", givenName: "App"},
  // //provider: "google"

  // https://github.com/jaredhanson/passport-google-oauth2

  // https://stackoverflow.com/questions/20431049/what-is-function-user-findorcreate-doing-and-when-is-it-called-in-passport#:~:text=88-,User.,the%20user%20doesn't%20exist.
  


}
));


/// GOOGLE
app.get("/auth/google", 

  passport.authenticate('google', { scope: ['profile', 'email'] })

);

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });






passport.use(new FacebookStrategy({
  clientID: FACEAPPID,
  clientSecret: FACESECRET,
  callbackURL: "http://localhost:3000/auth/facebook/secrets",
  state: true
  },
  async function verify(accessToken, refreshToken, profile, done) {

    console.log(profile.id);

    try {

      const user = await User.findOne( { where: { facebookid : profile.id } });
      // console.log("USER NULL ????", user);
      if (!user) {
        // console.log("segunto try");
        try {
          const user = await User.create({
            facebookid: profile.id,
            username: profile.displayName,         
            });
          console.log("User created ",user);
          return done(null, user);
        } catch (err) {
          console.log(err);
          return done(err, user);
        }
      } else {
        return done(null, user);
      }


    } catch (err) {
      console.log(err);
      return done(err);
    }

}
));



//// Facebook
app.get('/auth/facebook', 
  // console.log("AUth face"),
  passport.authenticate('facebook', { scope: ['email'] }) 
);

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login', failureMessage: true }),
  function(req, res) {
    res.redirect('/secrets');
});




app.get('/', async (req, res) => {

  res.render('home');

});
  



app.get('/login', (req, res) => {

  const message = req.flash("Error");
  res.render('login', {message: message});

});
 
app.post("/login", 
    passport.authenticate('local', {
        failureRedirect: '/login',
        failureFlash: true // Enable flash messages for failures
    }),
    (req, res) => {
        res.redirect("/secrets");
    }
);
  

app.get('/register', (req, res) => {
    res.render('register', { message: req.flash('message')});
  });


app.post('/register', async (req, res) => {

  try {
    const passwordHash = await bcrypt.hashSync(req.body.password, 12);

    const userCreated = await User.create({
        username: req.body.username,
        password: passwordHash,
        
            });

    req.login(userCreated, (error) => {
      if (error) {
        console.log(error.message);
        return res.render("register", { message: "An error occured, please try again."});
      } else {
        return res.redirect("/secrets");
      }
    })

  
  
  } catch(err) {
    console.error("Error Register RGC", err.errors[0].message.toUpperCase());
    req.flash("message", err.errors[0].message.toUpperCase());
    res.redirect("/register");

  }


});


app.get("/secrets", function(req, res) {

  // console.log("Secrest RGC", req.isAuthenticated());

  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }

});

app.get('/logout', function(req, res, next) {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

 
app.listen(3000, function() {
    console.log("Server started on port 3000.");
});