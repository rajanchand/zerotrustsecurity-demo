-- Adds name and phone columns to the users table for the profile feature
ALTER TABLE users
ADD COLUMN IF NOT EXISTS name TEXT DEFAULT '';

ALTER TABLE users
ADD COLUMN IF NOT EXISTS phone TEXT DEFAULT '';