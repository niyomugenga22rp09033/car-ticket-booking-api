const express = require('express');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

dotenv.config();

const app = express();
app.use(express.json()); // Parse JSON bodies

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Handle pool errors
pool.on('error', (err) => {
  console.error('Unexpected error on idle client', err);
});

pool.connect()
  .then(() => console.log("✅ Connected to database"))
  .catch(err => console.error("❌ Database connection error:", err));

// Middleware to authenticate token (for protected routes)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN"
  
  if (!token) return res.status(401).json({ error: 'Token missing' });
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// REGISTER new user (POST /register)
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  
  if (!name || !email || !password)
    return res.status(400).json({ error: 'Name, email and password are required' });
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users(name, email, password) VALUES($1, $2, $3)',
      [name, email, hashedPassword]
    );
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// LOGIN user (POST /login)
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required' });
  
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    
    if (!user) return res.status(403).json({ error: 'Invalid credentials' });
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(403).json({ error: 'Invalid credentials' });
    
    // Create JWT token
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// GET all cars (GET /cars) - public route
app.get('/cars', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM cars ORDER BY id');
    res.json({ cars: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error fetching cars' });
  }
});

// GET a specific car by ID (GET /cars/:id) - public route
app.get('/cars/:id', async (req, res) => {
  const { id } = req.params;
  
  try {
    const result = await pool.query('SELECT * FROM cars WHERE id = $1', [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Car not found' });
    }
    
    res.json({ car: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error fetching car' });
  }
});

// ADD a new car (POST /cars) - public route
app.post('/cars', async (req, res) => {
  const { name, details, price } = req.body;
  
  if (!name || !details || !price)
    return res.status(400).json({ error: 'Name, details and price are required' });
  
  try {
    await pool.query(
      'INSERT INTO cars(name, details, price) VALUES($1, $2, $3)',
      [name, details, price]
    );
    res.status(201).json({ message: 'Car added successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error adding car' });
  }
});

// GET all bookings for the authenticated user (GET /bookings) - protected route
app.get('/bookings', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        b.id,
        b.travel_date,
        c.name as car_name,
        c.details as car_details,
        c.price as car_price
      FROM bookings b
      JOIN cars c ON b.car_id = c.id
      WHERE b.user_id = $1
      ORDER BY b.id DESC
    `, [req.user.id]);
    
    res.json({ bookings: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error fetching bookings' });
  }
});

// GET a specific booking by ID for the authenticated user (GET /bookings/:id) - protected route
app.get('/bookings/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  
  try {
    const result = await pool.query(`
      SELECT 
        b.id,
        b.travel_date,
        c.name as car_name,
        c.details as car_details,
        c.price as car_price,
        u.name as user_name,
        u.email as user_email
      FROM bookings b
      JOIN cars c ON b.car_id = c.id
      JOIN users u ON b.user_id = u.id
      WHERE b.id = $1 AND b.user_id = $2
    `, [id, req.user.id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Booking not found' });
    }
    
    res.json({ booking: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error fetching booking' });
  }
});

// BOOK a ticket (POST /bookings) - protected route
app.post('/bookings', authenticateToken, async (req, res) => {
  const { car_id, travel_date } = req.body;
  
  if (!car_id || !travel_date)
    return res.status(400).json({ error: 'car_id and travel_date are required' });
  
  try {
    // Check if car exists
    const carResult = await pool.query('SELECT * FROM cars WHERE id = $1', [car_id]);
    if (carResult.rows.length === 0) {
      return res.status(404).json({ error: 'Car not found' });
    }
    
    await pool.query(
      'INSERT INTO bookings(user_id, car_id, travel_date) VALUES($1, $2, $3)',
      [req.user.id, car_id, travel_date]
    );
    res.status(201).json({ message: 'Booking created successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error during booking' });
  }
});

// Start server
app.listen(3000, () => console.log('🚀 Server running on port 3000'));
