CREATE TABLE gifts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL,
    ecard_url TEXT NOT NULL,
    match TEXT, -- This column will hold the username or ID of the matched Secret Santa
    created_at TIMESTAMP DEFAULT NOW()
);