require('dotenv').config();
const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-key-change-in-prod";

const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

app.use(express.json());
app.use(express.static("public"));

async function initDB() {
    const client = await pool.connect();
    try {
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await client.query(`
            CREATE TABLE IF NOT EXISTS folders (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                name VARCHAR(255) NOT NULL,
                color VARCHAR(7) DEFAULT '#6366f1',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, name)
            )
        `);

        await client.query(`
            CREATE TABLE IF NOT EXISTS notes (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                folder_id INTEGER REFERENCES folders(id) ON DELETE SET NULL,
                title VARCHAR(500),
                content TEXT NOT NULL,
                tags TEXT[],
                is_pinned BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Check if folder_id column exists, add it if it doesn't
        const columns = await client.query(`
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'notes' AND column_name = 'folder_id'
        `);

        if (columns.rows.length === 0) {
            await client.query(`
                ALTER TABLE notes ADD COLUMN folder_id INTEGER REFERENCES folders(id) ON DELETE SET NULL
            `);
            console.log("Added folder_id column");
        }

        // Check if tags column exists, add it if it doesn't
        const tagsColumns = await client.query(`
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'notes' AND column_name = 'tags'
        `);

        if (tagsColumns.rows.length === 0) {
            await client.query(`
                ALTER TABLE notes ADD COLUMN tags TEXT[]
            `);
            console.log("Added tags column");
        }

        // Check if is_pinned column exists, add it if it doesn't
        const pinnedColumns = await client.query(`
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'notes' AND column_name = 'is_pinned'
        `);

        if (pinnedColumns.rows.length === 0) {
            await client.query(`
                ALTER TABLE notes ADD COLUMN is_pinned BOOLEAN DEFAULT FALSE
            `);
            console.log("Added is_pinned column");
        }

        // Check if title column exists, add it if it doesn't
        const titleColumns = await client.query(`
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'notes' AND column_name = 'title'
        `);

        if (titleColumns.rows.length === 0) {
            await client.query(`
                ALTER TABLE notes ADD COLUMN title VARCHAR(500)
            `);
            console.log("Added title column");
        }

        console.log("Database initialized");
    } finally {
        client.release();
    }
}

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(401).json({ error: "Invalid token" });
        req.user = user;
        next();
    });
};

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.post("/auth/register", async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: "All fields required" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            "INSERT INTO users (name, email, password) VALUES ($1, $2, $3)",
            [name, email, hashedPassword]
        );
        res.status(201).json({ message: "User created" });
    } catch (err) {
        if (err.code === '23505') {
            res.status(400).json({ error: "Email already exists" });
        } else {
            res.status(500).json({ error: "Registration failed" });
        }
    }
});

app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        const user = result.rows[0];

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, name: user.name },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
    } catch (err) {
        res.status(500).json({ error: "Login failed" });
    }
});

// Get all folders for a user
app.get("/api/folders", authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT * FROM folders WHERE user_id = $1 ORDER BY name",
            [req.user.id]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch folders" });
    }
});

// Create a new folder
app.post("/api/folders", authenticateToken, async (req, res) => {
    const { name, color } = req.body;

    console.log('Creating folder for user:', req.user.id, { name, color });

    if (!name) {
        return res.status(400).json({ error: "Folder name required" });
    }

    try {
        const result = await pool.query(
            "INSERT INTO folders (user_id, name, color) VALUES ($1, $2, $3) RETURNING *",
            [req.user.id, name, color || '#6366f1']
        );
        console.log('Folder created successfully:', result.rows[0]);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Error creating folder:', err);
        if (err.code === '23505') {
            res.status(400).json({ error: "Folder name already exists" });
        } else {
            res.status(500).json({ error: "Failed to create folder" });
        }
    }
});

// Delete a folder
app.delete("/api/folders/:id", authenticateToken, async (req, res) => {
    try {
        await pool.query(
            "DELETE FROM folders WHERE id = $1 AND user_id = $2",
            [req.params.id, req.user.id]
        );
        res.json({ message: "Folder deleted" });
    } catch (err) {
        res.status(500).json({ error: "Failed to delete folder" });
    }
});

// Get all notes (with optional filtering)
app.get("/api/notes", authenticateToken, async (req, res) => {
    try {
        const { folder_id, tag, search } = req.query;
        let query = "SELECT * FROM notes WHERE user_id = $1";
        const params = [req.user.id];
        let paramCount = 1;

        if (folder_id) {
            paramCount++;
            query += ` AND folder_id = $${paramCount}`;
            params.push(folder_id);
        }

        if (tag) {
            paramCount++;
            query += ` AND $${paramCount} = ANY(tags)`;
            params.push(tag);
        }

        if (search) {
            paramCount++;
            query += ` AND (title ILIKE $${paramCount} OR content ILIKE $${paramCount})`;
            params.push(`%${search}%`);
        }

        query += " ORDER BY is_pinned DESC, updated_at DESC";

        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching notes:', err);
        res.status(500).json({ error: "Failed to fetch notes" });
    }
});

// Get a single note
app.get("/api/notes/:id", authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT * FROM notes WHERE id = $1 AND user_id = $2",
            [req.params.id, req.user.id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Note not found" });
        }
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch note" });
    }
});

// Create a new note
app.post("/api/notes", authenticateToken, async (req, res) => {
    const { title, content, folder_id, tags, is_pinned } = req.body;

    console.log('Creating note for user:', req.user.id, { title, content: content?.substring(0, 50), folder_id, tags, is_pinned });

    if (!content) {
        console.error('Content required');
        return res.status(400).json({ error: "Content required" });
    }

    try {
        const query = `
            INSERT INTO notes (user_id, title, content, folder_id, tags, is_pinned) 
            VALUES ($1, $2, $3, $4, $5, $6) 
            RETURNING *
        `;
        const params = [req.user.id, title || null, content, folder_id || null, tags || [], is_pinned || false];
        
        const result = await pool.query(query, params);
        console.log('Note created successfully:', result.rows[0]);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Error creating note:', err);
        res.status(500).json({ error: "Failed to save note" });
    }
});

// Update a note
app.put("/api/notes/:id", authenticateToken, async (req, res) => {
    const { title, content, folder_id, tags, is_pinned } = req.body;

    console.log('Updating note:', req.params.id, 'for user:', req.user.id, { title, content: content?.substring(0, 50), folder_id, tags, is_pinned });

    try {
        const query = `
            UPDATE notes 
            SET title = COALESCE($1, title),
                content = COALESCE($2, content),
                folder_id = COALESCE($3, folder_id),
                tags = COALESCE($4, tags),
                is_pinned = COALESCE($5, is_pinned),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $6 AND user_id = $7 
            RETURNING *
        `;
        const params = [title, content, folder_id, tags, is_pinned, req.params.id, req.user.id];
        
        const result = await pool.query(query, params);
        if (result.rows.length === 0) {
            console.error('Note not found');
            return res.status(404).json({ error: "Note not found" });
        }
        console.log('Note updated successfully:', result.rows[0]);
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error updating note:', err);
        res.status(500).json({ error: "Failed to update note" });
    }
});

// Delete a note
app.delete("/api/notes/:id", authenticateToken, async (req, res) => {
    try {
        await pool.query(
            "DELETE FROM notes WHERE id = $1 AND user_id = $2",
            [req.params.id, req.user.id]
        );
        res.json({ message: "Note deleted" });
    } catch (err) {
        res.status(500).json({ error: "Failed to delete note" });
    }
});

// Get all tags for a user
app.get("/api/tags", authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT DISTINCT unnest(tags) as tag 
             FROM notes 
             WHERE user_id = $1 AND tags IS NOT NULL
             ORDER BY tag`,
            [req.user.id]
        );
        res.json(result.rows.map(r => r.tag));
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch tags" });
    }
});

app.listen(3000, async () => {
    await initDB();
    console.log("Server running on http://localhost:3000");
});
