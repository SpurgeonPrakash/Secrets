require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

// const bcrypt = require("bcrypt");
// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
// const saltRounds = 10;

const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", { useUnifiedTopology: true,  useNewUrlParser: true });
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

userSchema.plugin(passportLocalMongoose);
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", (req,res) => {
  res.render("home");
});

app.get("/login", (req,res) => {
  res.render("login");
});

app.get("/register", (req,res) => {
  res.render("register");
});

app.get("/secrets", (req,res) => {
  if(req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", (req,res) => {
  //removing sessions and cookies here using passports logout method
  req.logout();
  res.redirect("/");
});

app.post("/register", (req,res) => {
  //Using passport-local-mongoose's register method to register data into db and authenticate(using passport) the user by creating a browser cookie
  User.register({username:req.body.username},req.body.password,(err,user) => {
    if(err) {
      console.log(err);
      res.redirect("/register")
    } else {
      passport.authenticate("local")(req, res,() => {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", (req,res) => {
  const user = new User({
    username: req.body.username,
    password:req.body.password
  });

  //Passport exposes a login() function on req (also aliased as logIn()) that can be used to establish a login session.
  req.login(user,(err)=> {
    if(err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res,() => {
        res.redirect("/secrets");
      });
    }
  });

});

//password encryption using bcrypt
// app.post("/register", (req,res) => {
//   bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
//     // password: md5(req.body.password)
//     const newUser = new User({
//       email:req.body.username,
//       password: hash
//     });
//     newUser.save((err) => {
//       if(!err) {
//         res.render("secrets");
//       } else {
//         console.log(err);
//       }
//     });
//   });
// });

//password encryption using md5
// app.post("/register", (req,res) => {
//
//   const newUser = new User({
//     email:req.body.username,
//     password: md5(req.body.password)
//   });
//   newUser.save((err) => {
//     if(!err) {
//       res.render("secrets");
//     } else {
//       console.log(err);
//     }
//   });
// });

//password encryption using bcrypt
// app.post("/login", (req,res) => {
//   const username = req.body.username;
//   // const password = md5(req.body.password);
//   const password = req.body.password;
//
//   User.findOne({email:username}, (err, foundUser) => {
//     if(err) {
//       console.log(err);
//     } else {
//       if(foundUser) {
//         bcrypt.compare(password, foundUser.password, function(err, result) {
//           if(result === true) {
//             res.render("secrets");
//           }
//         });
//       }
//     }
//   });
// });

//password encryption using md5 hashing
// app.post("/login", (req,res) => {
//   const username = req.body.username;
//   const password = md5(req.body.password);
//
//   User.findOne({email:username}, (err, foundUser) => {
//     if(err) {
//       console.log(err);
//     } else {
//       if(foundUser) {
//         if(foundUser.password === password) {
//           res.render("secrets");
//         }
//       }
//     }
//   });
// });

app.listen(3000, function() {
  console.log("Server started on port 3000");
});
