require("dotenv").config();

const express = require("express");
const cors = require("cors");
const connectDB = require("./config/database");
const Movie = require("./models/Movies");
const Director = require("./models/Directors");

connectDB();

const app = express();
const PORT = process.env.PORT || 3300;

app.use(cors());
app.use(express.json());

app.get("/status", (req, res) => {
  res.json({ ok: true, service: "film-api" });
});

// ENDPOINT MOVIES
// Get movies
app.get("/movies", async (req, res, next) => {
  // Tambahkan next untuk error handler
  try {
    const movie = await Movie.find({}); // Mengambil semua film dari MongoDB
    res.json(movie);
  } catch (err) {
    next(err); // Teruskan error ke error handler
  }
});

// Get movie by ID
app.get("/movies/:id", async (req, res, next) => {
  try {
    const movie = await Movie.findById(req.params.id);
    if (!movie) {
      return res.status(404).json({ error: "Film tidak ditemukan" });
    }
    res.json(movie);
  } catch (err) {
    if (err.kind === "ObjectId") {
      return res.status(404).json({ error: "Format ID tidak valid" });
    }
    next(err);
  }
});

// Post movies (tambah)
app.post("/movies", async (req, res, next) => {
  try {
    const newMovie = new Movie({
      title: req.body.title,
      director: req.body.director,
      year: req.body.year,
    });
    const savedMovie = await newMovie.save();
    res.status(201).json(savedMovie);
  } catch (err) {
    if (err.name === "ValidationError") {
      return res.status(400).json({ error: err.message });
    }
    next(err);
  }
});

// Put movie (update)
app.put("/movies/:id", async (req, res, next) => {
  try {
    const { title, director, year } = req.body;
    if (!title || !director || !year) {
      return res.status(400).json({
        error: "title, director, year wajib diisi",
      });
    }

    const updatedMovie = await Movie.findByIdAndUpdate(
      req.params.id,
      { title, director, year },
      { new: true, runValidators: true }
    );

    if (!updatedMovie) {
      return res.status(404).json({ error: "Film tidak ditemukan" });
    }

    res.json(updatedMovie);
  } catch (err) {
    if (err.name === "ValidationError") {
      return res.status(400).json({ error: err.message });
    }

    if (err.kind === "ObjectId") {
      return res.status(400).json({ error: "Format ID tidak valid" });
    }

    next(err);
  }
});

// Delete movies by ID (hapus)
app.delete("/movies/:id", async (req, res, next) => {
  try {
    const deletedMovie = await Movie.findByIdAndDelete(req.params.id);

    if (!deletedMovie) {
      return res.status(404).json({ error: "Film tidak ditemukan" });
    }

    res.status(204).send();
  } catch (err) {
    if (err.kind === "ObjectId") {
      return res.status(400).json({ error: "Format ID tidak valid" });
    }

    next(err);
  }
});

// ENDPOINT DIRECTORS
// Get direcotrs
app.get("/directors", async (req, res, next) => {
  // Tambahkan next untuk error handler
  try {
    const director = await Director.find({}); // Mengambil semua film dari MongoDB
    res.json(director);
  } catch (err) {
    next(err); // Teruskan error ke error handler
  }
});

// Get director by ID
app.get("/directors/:id", async (req, res, next) => {
  try {
    const director = await Director.findById(req.params.id);
    if (!director) {
      return res.status(404).json({ error: "Film tidak ditemukan" });
    }
    res.json(director);
  } catch (err) {
    if (err.kind === "ObjectId") {
      return res.status(404).json({ error: "Format ID tidak valid" });
    }
    next(err);
  }
});

// Post director (tambah)
app.post("/directors", async (req, res, next) => {
  try {
    const newDirector = new Director({
      name: req.body.name,
      birthYear: req.body.birthYear,
    });
    const savedDirector = await newDirector.save();
    res.status(201).json(savedDirector);
  } catch (err) {
    if (err.name === "ValidationError") {
      return res.status(400).json({ error: err.message });
    }
    next(err);
  }
});

// put director (update)
app.put("/directors/:id", async (req, res, next) => {
  try {
    const { name, birthYear } = req.body;
    if (!name || !birthYear) {
      return res.status(400).json({
        error: "name dan birthYear wajib diisi",
      });
    }

    const updatedDirector = await Director.findByIdAndUpdate(
      req.params.id,
      { name, birthYear },
      { new: true, runValidators: true }
    );

    if (!updatedDirector) {
      return res.status(404).json({ error: "Director tidak ditemukan" });
    }

    res.json(updatedDirector);
  } catch (err) {
    if (err.name === "ValidationError") {
      return res.status(400).json({ error: err.message });
    }

    if (err.kind === "ObjectId") {
      return res.status(400).json({ error: "Format ID tidak valid" });
    }

    next(err);
  }
});

// Delete director by ID (hapus)
app.delete("/directors/:id", async (req, res, next) => {
  try {
    const deletedDirector = await Director.findByIdAndDelete(req.params.id);

    if (!deletedDirector) {
      return res.status(404).json({ error: "Director tidak ditemukan" });
    }

    res.status(204).send();
  } catch (err) {
    if (err.kind === "ObjectId") {
      return res.status(400).json({ error: "Format ID tidak valid" });
    }

    next(err);
  }
});

// Fallback 404
app.use((req, res) => {
  res.status(404).json({ error: "Rute tidak ditemukan " });
});

// Error handler (opsional tapi bagus ditambahkan)
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Terjadi kesalahan pada server" });
});

app.listen(PORT, () => {
  console.log(`Server aktif di http://locallhost:${PORT}`);
});
