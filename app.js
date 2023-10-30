'use strict';

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const express = require('express');
const { MongoClient, ObjectId } = require("mongodb");

const JWT_SECRET = 'shhh';

const app = express();

const mongoClient = new MongoClient(`mongodb://root:example@localhost:27017/`);

const db = mongoClient.db('transactions');

// Create index for accounts unique account
db.collection("accounts").indexExists("accounts_unique").then(exists => {
    if (!exists) {
        db.collection("accounts").createIndex({
            "email": 1,
        }, { unique: true });
    }
})

// Authenticated endpoints middleware
const auth = function(req, res, next) {

    // Get the bearer from authorization header
    let autz = req.header('Authorization');

    if (typeof(autz) === 'undefined') {
        res.status(401);
        res.send('Authorization required')
        return
    }

    // Get authorization token after Bearer
    let bearer = autz.split('Bearer');

    if (bearer.length != 2 || bearer[1] === '') {
        res.status(401);
        res.send('Bearer authorization required')
        return
    }

    // Decode authentication token 
    jwt.verify(bearer[1].trim(), JWT_SECRET, function(err, decoded) {
        
        if (err != null) {
            res.status(401);
            console.log('JWT Decode Error:', err.message);
            res.send('Bearer authorization failed')
            return
        }

        // Get account with the id provided in access token
        db.collection("accounts").findOne({_id: ObjectId.createFromHexString(decoded.user)}).then(account => {

            if (!account) {
                res.status(401);
                res.end();
                return;
            }

            // Set current authenticated account
            res.set("user", account)

            // Move to the next request as is authenticated
            next();
        })

    });
}

app.use(express.json());

app.post('/api/auth/sign-in', (req, res) => {

    db.collection("accounts").findOne({
        "email": req.body.email,
    }).then(account => {
        
        if (account) {
            
            // Compare password againgst the stored hash
            bcrypt.compare(req.body.password, account.password).then(passwordOK=>{
                
                // If not authorized show status
                if (!passwordOK) {
                    // Verify brute force attempt
                    res.status(401)
                    res.end();
                    return
                }

                // Send access token containing user id
                res.json({access_token: jwt.sign({user:account._id}, JWT_SECRET)});
            })

            return
        }

        res.status(404); // Posible security breach
        res.end();
    })
})

app.post('/api/auth/sign-up', (req, res) => {

    if (typeof req.body.email === 'undefined') {
        res.json({error: "Email is mandatory"})
        res.status(400)
        return
    }
    
    if (typeof req.body.password === 'undefined') {
        res.json({error: "Password is mandatory"})
        res.status(400)
        return
    }

    bcrypt.genSalt(10, (err, salt) => {

        if (err != null || salt === '') {
            console.log(err);
            res.json({error: "Failed to generate salt"})
            return
        }

        bcrypt.hash(req.body.password, salt, (err, password) => {
            
            if (err != null) {
                console.log(err);
                res.json({error: "Failed to hash password"})
                return
            }

            const accounts = db.collection("accounts");

            const result = accounts.insertOne({
                email: req.body.email,
                password,
                _id: new ObjectId(),
            }).then(() => {
                res.end()
            }).catch(err => {
                res.json({error: "Failed to create account"})
            })
        });
    });

});

app.get('/api/transactions', auth, (req, res) => {
    res.send('Hello World!')
})

app.get('/api/transactions/:id', auth, (req, res) => {
    res.send('Hello World!')
})

app.post('/api/transactions', auth, (req, res) => {
    res.send('Hello World!')
})

app.put('/api/transactions/:id', auth, (req, res) => {
    res.send('Hello World!')
})

app.delete('/api/transactions/:id', auth, (req, res) => {
    res.send('Hello World!')
})

module.exports = app;