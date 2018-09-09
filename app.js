"use strict"

const AWS = require("aws-sdk");
const securePassword = require("secure-password");
const jwt = require("jsonwebtoken");
var MongoClient = require("mongodb").MongoClient;

let atlas_connection_uri;
let cachedDb = null;
let encryptedPasswordResetKey = process.env["PASSWORD_RESET_KEY"]; // todo: save hash of PW reset token with this key

exports.handler = (event, context, callback) => {
    var uri = process.env["MONGODB_ATLAS_CLUSTER_URI"];

    if (atlas_connection_uri != null) {
        processEvent(event, context, callback);
    }
    else {
        decryptConnectionString(uri, 
            function(plainTextConnectionString) {
                atlas_connection_uri = plainTextConnectionString;
                processEvent(event, context, callback);
            },
            function(error) {
                sendResponseToApiGateway("ERROR decrypting database connection string.", 500, callback);
            }
        )
    }
};

function decryptConnectionString(connectionString, onSuccess, onError) {
    const kms = new AWS.KMS();
    kms.decrypt({ CiphertextBlob: new Buffer(connectionString, "base64") }, (err, data) => {
        if (err) {
            console.log("Decrypt error:", err);
            onError(err);
        } else {
            const plainTextConnectionString = data.Plaintext.toString("ascii");
            onSuccess(plainTextConnectionString);
        }
    });
}

function processEvent(event, context, callback) {
    console.log("calling Atlas from Lambda with event: " + JSON.stringify(event));
    var userRequest = JSON.parse(JSON.stringify(event));
    context.callbackWaitsForEmptyEventLoop = false;

    try {
        if (cachedDb == null) {
            console.log("=> connecting to database");
            MongoClient.connect(atlas_connection_uri, function(err, client) {
                cachedDb = client.db("ambr");
                return evaluateRequestType(cachedDb, userRequest, callback);
            });
        }
        else {
            evaluateRequestType(cachedDb, userRequest, callback);
        }
    }
    catch (err) {
        console.error("an error occurred", err);
    }
}

function evaluateRequestType(db, userRequest, callback) {
    if (userRequest.requestType === "register") {
        const user = userRequest.user;
        registerUser(db, user, callback);
    }
    else if (userRequest.requestType === "login") {
        const user = userRequest.user;
        logIn(db, user, callback);
    }
    else if (userRequest.requestType === "reset") {
        const email = userRequest.emailAddress;
        resetPassword(db, email, callback);
    }
    else {
        console.error("Unidentified request type: " + JSON.stringify(userRequest.requestType));
    }
}

function registerUser(db, user, callback) {
    getUserByEmail(db, user.emailAddress, 
        (existingUser) => {
            if (existingUser) {
                const errorResponse = {
                    message: "Could not create new user. User already exists.",
                    isUserAlreadyExists: true
                };
                sendResponseToApiGateway(JSON.stringify(errorResponse), 400, callback);
            }
            else {
                saveNewUser(db, user, callback);
            }
        },
        (error) => {
            sendResponseToApiGateway("ERROR verifying user does not exist.", 500, callback);
        }
    );
    
    
}
function saveNewUser(db, user, callback) {
    const passwordPolicy = securePassword();
    const userPassword = Buffer.from(user.password);

    passwordPolicy.hash(userPassword, function(err, hash) {
        if (err) {
            sendResponseToApiGateway("ERROR registering new user - password could not be secured.", 500, callback);
        }
        else {
            try {
                db.collection("users").insertOne({ email: user.emailAddress, passwordHash: hash.toString("base64") });
                setApiToken(db, user, callback);
            } catch(err) {
                sendResponseToApiGateway("ERROR registering new user - record could not inserted.", 500, callback);
            }
        }
    });
}

function logIn(db, user, callback) {
    const existingUser = getUserByEmail(db, user.emailAddress, 
        (existingUser) => {
            if (existingUser) {
                const passwordPolicy = securePassword();
                const userPasswordBuffer = Buffer.from(user.password);
                const passwordHashBuffer = Buffer.from(existingUser.passwordHash, "base64");
        
                passwordPolicy.verify(userPasswordBuffer, passwordHashBuffer, function(err, result) {
                    if (err) {
                        sendResponseToApiGateway("ERROR logging in - password verification process failed.", 500, callback);
                    } else if (result === securePassword.VALID) {
                        setApiToken(db, user, callback);
                    } else if (result === securePassword.VALID_NEEDS_REHASH) {
                        passwordPolicy.hash(userPasswordBuffer, function(err, improvedHash) {
                            if (!err) {
                                db.collection("users").updateOne(
                                    { email: user.emailAddress },
                                    { $set: { passwordHash: improvedHash.toString("base64") } }
                                );
                            }
                            setApiToken(db, user, callback);
                        });
                    }
                    else {
                        sendResponseToApiGateway("ERROR logging in - unauthenticated.", 401, callback);
                    }
                });
            }
            else {
                const errorResponse = {
                    message: "Could not log in. No user exists with that email.",
                    isUserNotFound: true
                };
                sendResponseToApiGateway(JSON.stringify(errorResponse), 400, callback);
            }
        },
        (error) => {
            sendResponseToApiGateway("ERROR verifying user exists during login.", 500, callback);
        }
    );
}
function setApiToken(db, user, callback) {
    const JWT_SECRET_KEY = process.env["JWT_SECRET_KEY"];
    const kms = new AWS.KMS();
    kms.decrypt({ CiphertextBlob: new Buffer(JWT_SECRET_KEY, "base64") }, (err, data) => {
        if (err) {
            console.log("Decrypt error: ", err);
            sendResponseToApiGateway("ERROR decrypting JWT secret.", 500, callback);
        } else {
            const plaintTextJwtKey = data.Plaintext.toString("ascii");
            const apiToken = jwt.sign({ id: user.emailAddress }, plaintTextJwtKey, {
                expiresIn: 86400 // 24 hrs
            });

            const successfulResponse = {
                isUserLoggedIn: true,
                apiToken: apiToken
            };
            sendDataToApiGateway(successfulResponse, callback);
        }
    })
}

function resetPassword(db, email, callback) {
    // todo: send email after saving hash of reset token
}

function getUserByEmail(db, emailAddress, onSuccess, onError) {
    db.collection("users").findOne({ email: { $eq: emailAddress } }, function(err, user) {
        if (err) {
            onError(err);
        } else if (user) {
            onSuccess(user);
        } else {
            onSuccess(null);
        }
    });
}

function sendClientErrorToApiGateway(errorMessage, callback) {
    sendResponseToApiGateway(errorMessage, 400, callback);
}
function sendDataToApiGateway(data, callback) {
    const messageBody = JSON.stringify(data);
    sendResponseToApiGateway(messageBody, 200, callback);
}
function sendResponseToApiGateway(messageBody, statusCode, callback) {
    const apiResponse = {
        "isBase64Encoded": false,
        "statusCode": statusCode,
        "headers": { "Content-Type": "application/json" },
        "body": messageBody
    };
    callback(null, apiResponse);
}