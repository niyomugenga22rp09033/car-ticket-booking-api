CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100) UNIQUE,
    password TEXT
);

CREATE TABLE cars (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    details TEXT,
    price NUMERIC
);

CREATE TABLE bookings (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    car_id INTEGER REFERENCES cars(id),
    travel_date DATE
);