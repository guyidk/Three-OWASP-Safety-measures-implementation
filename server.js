const mongoose = require('mongoose');
const express = require('express');
require('dotenv').config();
const path = require('path');
const userRouter = require('./routes/userRouter');
const cors = require('cors');

mongoose.set('strictQuery', true);

mongoose.connect(process.env.DB_CONNECT)
    .then(() =>{
     console.log('Connected to MongoDB database');
});

const app = express();
const PORT = process.env.PORT || 3000;

const corsOptions = {
    origin: 'http://127.0.0.1:5500',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
}

app.use(express.static(path.join(__dirname)));

app.get('/reset-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'reset_password.html'))
})

app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use("", userRouter);

app.get("/", (req, res) => {
    return res.status(200).json({
        message: "Congrats. Your web server is running"
    });
});

app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
    console.log(`Click here to access http://localhost:${PORT}`);
});
