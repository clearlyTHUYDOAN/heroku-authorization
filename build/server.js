const express       = require('express');
const bodyParser    = require('body-parser');
const fs            = require('fs');
const bcrypt        = require('bcryptjs');
const jwt           = require('jsonwebtoken');

//middleware from authorize.js
const authorize     = require('./middleware/authorize');

//application
const app = express();
app.use(bodyParser.json());

//defines which origins and headers are permitted
app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, authorization");
  next();
});

//POST endpoint for password encryption and creating user profiles
app.post('/encrypt',(req,res) => {
    let username = req.body.username;
    let password = req.body.password;

    console.log(res.body);
    console.log(username);
    console.log(password);

    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(password, salt, (err, hash) => {
            // Store hash in your password DB. Save hashed password in a file with username as the title.
            if (!err) {
              fs.writeFile('notpasswords/' + username + '.txt', hash, (err) => {
                res.json('Password Saved');
              })
            } else {
              console.log("There was an error with the hashing.");
            }
        });
    });
});

//POST endpoint for logging in to the server
app.post('/login', (req,res) => {
    let username = req.body.username;
    let password = req.body.password;
    /*
        TASK 1: Check if the user provides the right password for their username.
        If the password is correct, then create a token with the username, using a secret key of your choice, and send the token back
    */

    fs.readFile('notpasswords/'+ username +'.txt', (err,data) =>{
        bcrypt.compare(password, data.toString(), function(err, result) {
            if (result) {
				//sign a token in successful login and send to client side
                let token = jwt.sign({username:username},'brainstationkey'); //you can name this keywhatever you want. the more secure, the better, though.
                res.json({token:token});
                console.log("Password matches with login credentials in the database.");
            }
            else {
                res
                .status(403)
                .send({token:null});
                console.log("Either the username or password is incorrect or does not exist.");
            }
        });
    })
    
})


// GET data end point goes here.
// TASK 5: This endpoint should require that all requests to this endpoint pass through the middleware created in the previous task.
// TASK 6: If the request passes through the middleware and makes it to this endpoint, send back the username that was stored in the token. 
app.get('/privatedata', authorize, (req,res) => {
    console.log("This username: " + req.decoded.username + " is from app.get for /private data"); //req.decoded is from middleware.
    res.json(req.decoded.username);
});
// Adding authorize in the middle there requires requests to go through middleware before reaching the endpoint. 
// If you don't write it there, it doesn't go through middleware and immediately goes to the endpoint.


app.use(express.static(__dirname + '/build/static'));

app.listen(process.env.PORT || 8080);