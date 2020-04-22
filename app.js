require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');

// const bcrypt = require("bcrypt");
// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
// const saltRounds = 10;
const defaultSecret = [{secret: "This is my First Secret"}];

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
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

const User = mongoose.model("User", userSchema);

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
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
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

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req,res) => {
  res.render("home");
});

app.get("/auth/google",passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect Secrets page.
    res.redirect("/secrets");
});

app.get('/auth/facebook',passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login", (req,res) => {
  res.render("login");
});

app.get("/register", (req,res) => {
  res.render("register");
});

app.get("/secrets", (req,res) => {
  // if(req.isAuthenticated()) {
  //   res.render("secrets");
  // } else {
  //   res.redirect("/login");
  // }
  User.find({"secret": {$ne: null}}, (err,foundUsers) => {
    if(err){
      console.log(err);
    } else {
      if(foundUsers) {
        res.render("secrets", {usersWithSecrets : foundUsers});
      } else {
        res.render("secrets", {usersWithSecrets: {}})
      }
    }
  });
});

app.get("/logout", (req,res) => {
  //removing sessions and cookies here using passports logout method
  req.logout();
  res.redirect("/");
});

app.get("/submit", (req,res) => {
  if(req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
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

app.post("/submit", (req,res) => {
  const submittedSecret = req.body.secret;

  console.log(req.user);
  User.findById(req.user.id, (err,foundUser) => {
    if(err) {
      console.log(err);
    } else {
      if(foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(() => {
          res.redirect("/secrets");
        });
      }
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
