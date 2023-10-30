'use strict';

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const express = require('express');
const { MongoClient, ObjectId } = require("mongodb");

const JWT_SECRET = 'shhh';

const app = express();

const mongoClient = new MongoClient(`mongodb://root:example@localhost:27017/`);

const db = mongoClient.db('transactions');

// Create index for accounts to store unique account
db.collection("accounts").indexExists("accounts_unique").then(exists => {
    if (!exists) {
        db.collection("accounts").createIndex({
            "email": 1,
        }, { unique: true });
    }
})

// The password must consist of 3 numbers, 3 lowercase letters, 
// 2 uppercase letters and at least one special character
const validPassword = (pass) => {
   
    const count = (reg) => {
        let count = 0;
        for (let i=0; i<pass.length; i++) {
            if(reg.test(pass.charAt(i))) {
                count++;
            }
        }

        return count;
    }

    if (3 != count(/^\d$/)) {
        return false;
    }

    if (3 != count(/^[a-z]$/)) {
        return false;
    }

    if (2 != count(/^[A-Z]$/)) {
        return false;
    }

    if (0 == count(/^([@#$%&*])$/gi)) {
        return false;
    }

    return true
};

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
            req.user = account;

            // Move to the next request as is authenticated
            next();
        })

    });
}

// Specify endpoints are working with json
app.use(express.json());

// Sing In Endpoint
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

// Sign Up Endpoint
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

    if (!validPassword(req.body.password)) {
        res.json({error: "Password is invalid, the password must consist of 3 numbers, 3 lowercase letters, 2 uppercase letters and at least one special character"})
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

app.get('/api/transactions', auth, async (req, res) => {
    
    const cursor = db.collection("transactions").find({
        user: req.user._id,
    }).project({_id:1,amount:1});

    const transactions = [];

    while (await cursor.hasNext()) {
        transactions.push(await cursor.next());
    }

    res.json(transactions);
})

app.get('/api/transactions/:id', auth, (req, res) => {
    
    db.collection("transactions").findOne({
        _id: ObjectId.createFromHexString(req.params.id)
    }).then(transaction => {
        
        if (!transaction) {
            res.status(404);
            res.json({error:"Transaction not found"});
            return
        }

        res.json(transaction);
    })
})

app.post('/api/transactions', auth, (req, res) => {

    if (typeof(req.body.amount) != "number") {
        res.json({error:"Amount must be a number"});
        return;
    }

    if (req.body.amount < 1 || req.body.amount > 5000) {
        res.json({error:"Amount between $1 and $5,000 inclusive."});
        return;
    }

    const transaction = {
        _id: new ObjectId(),
        user: req.user._id,
        amount: req.body.amount,
    }

    db.collection("transactions").insertOne(transaction)

    res.json(transaction)
})

app.put('/api/transactions/:id', auth, (req, res) => {

    if (typeof(req.body.status) === 'undefined') {
        res.status(400);
        res.json({error:"Invalid status of transaction"})
        return
    }

    db.collection("transactions").updateOne({
        _id: ObjectId.createFromHexString(req.params.id),
    }, {
        "$set": {
            "status": req.body.status,
        }
    }).then(() => {
        res.end();
    }).catch(e => {
        res.json({error:"Failed to update status"});
    })
})

app.delete('/api/transactions/:id', auth, (req, res) => {
    db.collection("transactions").deleteOne({
        _id: ObjectId.createFromHexString(req.params.id)
    }).then(() => {
        res.status(410);
        res.end();
    }).catch(err => {
        res.status(500);
        res.json({error:"Failed to delete transaction"});
    });
})

module.exports = app;