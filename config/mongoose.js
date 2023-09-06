const mongoose = require('mongoose');

mongoose.connect('mongodb://127.0.0.1:27017/nodejs-Authentication');

const db= mongoose.connection;

db.on('error',console.log.bind(console,"error connection to MongoDB"));

db.once('open',()=>{
    console.log("Successfully connecting with mongoDB");
});