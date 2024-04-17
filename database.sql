/**
  This is the SQL script that will be used to initialize the database schema.
  We will evaluate you based on how well you design your database.
  1. How you design the tables.
  2. How you choose the data types and keys.
  3. How you name the fields.
  In this assignment we will use PostgreSQL as the database.
  */

CREATE TABLE users (
  id SERIAL PRIMARY KEY, -- Auto-incrementing integer for unique user ID
  full_name VARCHAR(255) NOT NULL, -- User's full name
  phone_number VARCHAR(20) UNIQUE, -- User's phone number (unique)
  password_hash BYTEA NOT NULL, -- Hashed and salted password
  password_salt BYTEA NOT NULL, -- salt for the password
  login_count INTEGER DEFAULT 0 CHECK (login_count >= 0), -- Login count (defaults to 0, cannot be negative)
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, -- Timestamp of user creation
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP -- Timestamp of user update
);

CREATE INDEX idx_users_phone_number ON users(phone_number); -- Index for faster phone number lookups
