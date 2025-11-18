-- Add created_by and head_user_id columns to departments table
ALTER TABLE departments ADD COLUMN IF NOT EXISTS created_by INTEGER REFERENCES users(id);
ALTER TABLE departments ADD COLUMN IF NOT EXISTS head_user_id INTEGER REFERENCES users(id);
