require('dotenv').config();
const express = require('express');
const cors = require('cors');
const db = require('./database.js');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

app.get('/status', (req, res) => {
  res.json({ ok: true, service: 'film-api' });
});

// endpoint movies
app.get('/movies', (req, res) => {
  const sql = "SELECT * FROM movies ORDER BY id ASC";
  db.all(sql, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.get('/movies/:id', (req, res) => {
  const sql = "SELECT * FROM movies WHERE id = ?";
  db.get(sql, [req.params.id], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!row) {
      return res.status(404).json({ error: 'Film tidak ditemukan' });
    }
    res.json(row);
  });
});

app.post('/movies', (req, res) => {
  const { title, director, year } = req.body;
  if (!title || !director || !year) {
    return res.status(400).json({ error: 'title, director, year wajib diisi' });
  }

  const sql = 'INSERT INTO movies (title, director, year) VALUES (?,?,?)';
  db.run(sql, [title, director, year], function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(201).json({ id: this.lastID, title, director, year });
  });
});

app.put('/movies/:id', (req, res) => {
  const { title, director, year } = req.body;
  const sql = 'UPDATE movies SET title = ?, director = ?, year = ? WHERE id = ?';
  db.run(sql, [title, director, year, req.params.id], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Film tidak ditemukan' });
    }
    res.json({ id: Number(req.params.id), title, director, year });
  });
});

app.delete('/movies/:id', (req, res) => {
  const sql = 'DELETE FROM movies WHERE id = ?';
  db.run(sql, req.params.id, function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Film tidak ditemukan' });
    }
    res.status(204).send();
  });
});

//DIRECTOR
app.get('/directors', (req, res) => {
  const sql = "SELECT * FROM directors ORDER BY id ASC";
  db.all(sql, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.get('/directors/:id', (req, res) => {
  const sql = "SELECT * FROM directors WHERE id = ?";
  db.get(sql, [req.params.id], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!row) {
      return res.status(404).json({ error: 'Sutradara tidak ditemukan' });
    }
    res.json(row);
  });
});

app.post('/directors', (req, res) => {
  const { name, birthYear } = req.body;
  if (!name || !birthYear) {
    return res.status(400).json({ error: 'name dan birthYear wajib diisi' });
  }

  const sql = 'INSERT INTO directors (name, birthYear) VALUES (?,?)';
  db.run(sql, [name, birthYear], function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(201).json({ id: this.lastID, name, birthYear });
  });
});

app.put('/directors/:id', (req, res) => {
  const { name, birthYear } = req.body;
  const sql = 'UPDATE directors SET name = ?, birthYear = ? WHERE id = ?';
  db.run(sql, [name, birthYear, req.params.id], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Sutradara tidak ditemukan' });
    }
    res.json({ id: Number(req.params.id), name, birthYear });
  });
});

app.delete('/directors/:id', (req, res) => {
  const sql = 'DELETE FROM directors WHERE id = ?';
  db.run(sql, req.params.id, function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Sutradara tidak ditemukan' });
    }
    res.status(204).send();
  });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Rute tidak ditemukan' });
});

//menjalankan server
app.listen(PORT, () => {
  console.log(`Server aktif di http://localhost:${PORT}`);
});