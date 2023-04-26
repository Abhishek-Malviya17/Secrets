//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
// const session = require('cookie-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const http = require('http');

const app = express();

let temp = '';
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// mongoose.connect("mongodb://0.0.0.0:27017/secret", { useNewUrlParser: true });
mongoose.connect(process.env.DATABASE, { useNewUrlParser: true, useUnifiedTopology: true });
// mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  secret: String,
  // temp: String         //added temp
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){

//auto AutoRefrash
 res.setHeader('Refresh', '5');
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if (err){
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("home", {usersWithSecrets: foundUsers, isAuthenticated: req.isAuthenticated()});
      }
    }
  });

});

// delete request using onchange in checkbox
app.get("/delete", function(req, res){
  User.findById(req.user.id, function(err, foundUser){
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = null;
        foundUser.save(function(){
          res.redirect("/");
          // res.render("home", {usersWithSecrets: foundUsers, isAuthenticated: req.isAuthenticated(), correntUser: foundUser._id});
        });
      }
    }
  });
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/");
  });

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", function(req, res){
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if (err){
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/register");
  }
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

//Once the user is authenticated and their session gets saved, their user details are saved to req.user.
  // console.log(req.user.id);

  User.findById(req.user.id, function(err, foundUser){
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/");
        });
      }
    }
  });
});

app.get("/logout", function(req, res){
  req.session.destroy(function(err) {
    if(err) {
      console.log(err);
    } else {
      // console.log(req.user.secret);
      temp = req.user.secret;
      // localStorage.setItem('temp', 'secret');
      // console.log("req.user.temp:-  "  +  req.user.temp);    // change temp with req.user.temp
      User.updateOne({_id: req.user._id}, {secret: null}, function(err){
      if(err){
        console.log(err);
      }else{
        console.log("Successfuly logout");
        res.redirect("/");
      }
    })

    }
  });
});

app.post("/register", function(req, res){

  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/");
      });
    }
  })
});

app.post("/login", function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        // console.log("login temp "  + req.user.temp);

        User.updateOne({_id: req.user._id}, {secret: temp}, function(err){
          if(err){
            console.log(err);
          }else{
            console.log("Successfuly login");
            res.redirect("/");
          }
        })
        // console.log("login:-  " + req.user._id);
        // req.user.secret = temp;
        // console.log("login secret:-  " + temp);
        // res.redirect("/");
      });
    }
  });

});



app.listen(process.env.PORT || 3000, function() {
  console.log("Server started on port 3000.");
});
