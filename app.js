const express = require('express');
const mongoose = require('mongoose');
const morgan = require('morgan');
const cors = require('cors');

require('dotenv').config()

// Initialize Express
const app = express();

// Connect to db
mongoose.connect(process.env.DATABASE, {
        useNewUrlParser: true,
        useFindAndModify: false,
        useUnifiedTopology: true,
        useCreateIndex: true
    })
    .then(() => console.log('DB connected ...'))
    .catch(err => console.log('DB CONNECTION ERROR', err))

// Import Routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');

// App Middlewear
app.use(express.json())
app.use(morgan('dev'));
// app.use(cors()); // allows all origins
if (process.env.NODE_ENV == 'development') {
    app.use(cors({ origin: `${process.env.CLIENT_URL}` }))
}

// Routes Middlewear
app.use('/api', authRoutes);
app.use('/api', userRoutes);

// Server Port
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => console.log(`server running @ http://localhost:${PORT}`));