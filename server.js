// backend/server.js
const express = require('express');
const cors = require('cors');
const app = express();

// IMPORTANT: Railway will set the PORT environment variable.
// Fallback to 3001 for local development.
const PORT = process.env.PORT || 3001;

// CORS Configuration
// We'll update this later with your specific Netlify frontend URL
const allowedOrigins = [
    'http://localhost:5500', // For local frontend testing (if you use Live Server on this port)
    'http://127.0.0.1:5500', // Another local testing
    // We will add your Netlify URL and custom domain here later
];

const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    }
};
app.use(cors(corsOptions)); // Use the CORS middleware with specific options

// A simple API endpoint
app.get('/api/crypto-data', (req, res) => {
    const mockCryptoData = [
        { id: 'bitcoin', name: 'Bitcoin', symbol: 'BTC', price: 40000 },
        { id: 'ethereum', name: 'Ethereum', symbol: 'ETH', price: 3000 },
        { id: 'dogecoin', name: 'Dogecoin', symbol: 'DOGE', price: 0.15 },
    ];
    res.json(mockCryptoData);
});

app.get('/', (req, res) => {
    res.send('Hello from RapidCrypto Backend!');
});

app.listen(PORT, () => {
    console.log(`Backend server running on port ${PORT}`);
});