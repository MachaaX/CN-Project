-- Create the database
CREATE DATABASE IF NOT EXISTS healthcare_db;
USE healthcare_db;

-- Drop existing tables if they exist
DROP TABLE IF EXISTS comments;
DROP TABLE IF EXISTS prescriptions;
DROP TABLE IF EXISTS health_data;
DROP TABLE IF EXISTS patients;
DROP TABLE IF EXISTS users;

-- Create users table with role_name as ENUM
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role_name ENUM('patient', 'nurse', 'doctor') NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create patients table
CREATE TABLE patients (
    user_id INT PRIMARY KEY,
    address VARBINARY(255),  -- Encrypted address
    age INT,
    height DECIMAL(5,2),
    weight DECIMAL(5,2),
    sex VARCHAR(10),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create health_data table with encrypted file data and filename
CREATE TABLE health_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT NOT NULL,
    symptoms TEXT NOT NULL,
    file_data LONGBLOB,  -- Store encrypted file data as binary
    filename VARCHAR(255),  -- Store the filename of the health data
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(user_id) ON DELETE CASCADE
);

-- Create comments table
CREATE TABLE comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT,
    author_id INT,
    comment TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    role ENUM('doctor', 'nurse') NOT NULL,
    FOREIGN KEY (patient_id) REFERENCES patients(user_id) ON DELETE CASCADE,
    FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create prescriptions table
CREATE TABLE prescriptions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT,
    doctor_id INT,
    prescription TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(user_id) ON DELETE CASCADE,
    FOREIGN KEY (doctor_id) REFERENCES users(id) ON DELETE CASCADE
);
