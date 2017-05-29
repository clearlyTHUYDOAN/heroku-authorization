/* 
	TASK 4: In this file, you will create a middleware that will check a request for the authToken.
	If a token is found it should verify the token with the secret key used to generate the token
	If the token is verified, the contents of the token should be stored in the request and the request should be passed on.
	
	If no token is found or cannot be verified, then send back a response with a status code of 403 along with an appropriate error message.
	Remember to require jsonwebtoken here.
*/

const jwt = require('jsonwebtoken');

module.exports = (req,res,next) => {
	//check if there is token in the body, a url parameter, or the request headers
     let token = req.body.token || req.param('token') || req.headers['authorization'];
	    if (token) {
			//if there is a token try and decode it with the key that was used to encrypt it
            jwt.verify(token, 'brainstationkey', function(err, decoded) {          
	            if (err) {
	                return res.status(403).json({ success: false, message: 'Failed to authenticate token.' });      
	            } else {
	                req.decoded = decoded;  
					console.log(decoded + " from middleware."); //this is the decoded token.
	                next(); //when you have middleware, next is the thing that allows you to move on to the next thing.
							//changes to req and res will get passed on with next().
	            }
	        });
	        
	    } else {
			//if there is no token send an error
	        return res.status(403).send({ 
	            success: false, 
	            message: 'No token provided.'
	        });
	    }
};

