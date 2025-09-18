import express, { json } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { FinPay } from './finpay.js';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;

// Initialize FinPay Auth
const finpayAuth = new FinPay(
  process.env.FINPAY_CLIENT_ID,
  process.env.FINPAY_CLIENT_SECRET,
  process.env.FINPAY_BASE_URL,
);

// Middleware
app.use(cors());
app.use(express.json());

app.post('/', async (req, res) => {
  return await finpayAuth.doPayment(req, res);
});

app.post('/callback', async (req, res) => {
    return await finpayAuth.doCallback(req, res);
});

// Error handling middleware
app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    status: 'error',
    message: 'Internal server error'
  });
});

// 404 handler
app.use((_req, res) => {
  res.status(404).json({
    status: 'error',
    message: 'Endpoint not found'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 FinPay Express API is running on port ${PORT}`);
  console.log(`📖 API Documentation: http://localhost:${PORT}/`);
});

export default app;