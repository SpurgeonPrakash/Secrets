require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
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

mongoose.connect("mongodb://localhost:27017/userDB", { useUnifiedTopology: true,  useNewUrlParser: true });

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});


// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

const User = mongoose.model("User", userSchema);

app.get("/", (req,res) => {
  res.render("home");
});

app.get("/login", (req,res) => {
  res.render("login");
});

app.get("/register", (req,res) => {
  res.render("register");
});

app.post("/register", (req,res) => {
  bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    // password: md5(req.body.password)
    const newUser = new User({
      email:req.body.username,
      password: hash
    });
    newUser.save((err) => {
      if(!err) {
        res.render("secrets");
      } else {
        console.log(err);
      }
    });
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

app.post("/login", (req,res) => {
  const username = req.body.username;
  // const password = md5(req.body.password);
  const password = req.body.password;

  User.findOne({email:username}, (err, foundUser) => {
    if(err) {
      console.log(err);
    } else {
      if(foundUser) {
        bcrypt.compare(password, foundUser.password, function(err, result) {
          if(result === true) {
            res.render("secrets");
          }
        });
      }
    }
  });
});

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
