// server.js
if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}

const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const passport = require("passport");
const initializePassport = require("./config/passport-config");
const flash = require("express-flash");
const session = require("express-session");
const methodOverride = require("method-override");
const connection = require("./config/db");
const user = require("./models/user");

initializePassport(passport, user.getUserByEmail, user.getUserById);

app.set("view engine", "ejs");
app.set("views", __dirname + "/views");
app.use(express.static("public"));

app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(
  session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
    },
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride("_method"));

// register code
app.post("/registracija", user.checkNotAuthenticated, async (req, res) => {
  try {
    const { name, username, password, passwordConfirm } = req.body;

    const hashMainPass = await bcrypt.hash(password, 15);

    if (password != passwordConfirm) {
      req.flash("error", "Gesli se ne ujemata!");
      return res.redirect("/registracija");
    }

    connection.query(
      "SELECT * FROM users WHERE username = ?",
      [username],
      async (err, results) => {
        if (err) {
          console.log(err);
          req.flash("error", "An error occurred during registration.");
          return res.redirect("/registracija");
        }

        if (results.length > 0) {
          req.flash("error", "Uporabniško ime že obstaja!");
          return res.redirect("/registracija");
        } else {
          // Insert the new user
          connection.query(
            "INSERT INTO users (name, username, password, created_at, updated_at) VALUES (?, ?, ?, NOW(), NOW())",
            [name, username, hashMainPass],
            (err, results) => {
              if (err) {
                console.log(err);
                req.flash(
                  "error",
                  "Med registracijo se je zgodila napaka! Prosim, poskusi znova!"
                );
                return res.redirect("/registracija");
              }
              console.log(results);
              req.flash(
                "success",
                "Registracija uspešna! Sedaj se lahko prijaviš!"
              );
              return res.redirect("/prijava");
            }
          );
        }
      }
    );
  } catch (e) {
    console.log(e);
    req.flash("error", "Zgodila se je nepričakovana napaka!");
    res.redirect("/registracija");
  }
});

// login code
app.post(
  "/prijava",
  user.checkNotAuthenticated,
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/prijava",
    failureFlash: true,
  })
);

// check if the user is authenticated
function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/prijava");
}

app.get("/", user.checkAuthenticated, (req, res) => {
  user
    .getUserById(req.user.id)
    .then((user) => {
      connection.query("SELECT * FROM notearchive", (err, entries) => {
        if (err) {
          throw err;
        }

        connection.query(
          "SELECT MAX(archive_id) FROM notearchive",
          (err, result) => {
            if (err) {
              throw err;
            }

            // Pass entries and maxArchiveId to the frontend
            res.render("index.ejs", {
              name: user[0].name,
              entries: entries,
              maxArchiveId: result[0]["MAX(archive_id)"], // Access the result of the query correctly
            });
          }
        );
      });
    })
    .catch((e) => {
      console.log(e);
      res.redirect("/prijava");
    });
});

// logout
app.delete("/odjava", (req, res) => {
  req.logout(() => {
    res.redirect("/prijava");
  });
});

// logout
app.get("/odjava", (req, res) => {
  req.logout(() => {
    res.redirect("/prijava");
  });
});

// register page
app.get("/registracija", user.checkNotAuthenticated, (req, res) => {
  res.render("register.ejs");
});

// login page
app.get("/prijava", user.checkNotAuthenticated, (req, res) => {
  res.render("login.ejs");
});

app.get("/", (req, res) => {});

// Handle the form submission to add a new entry
app.post("/add", user.checkAuthenticated, (req, res) => {
  const { archive_id, title, composer, arranger, closet, shelf, notes } =
    req.body;
  const insertQuery = `INSERT INTO notearchive (archive_id, title, composer, arranger, closet, shelf, notes) VALUES (?, ?, ?, ?, ?, ?, ?)`;
  connection.query(
    insertQuery,
    [archive_id, title, composer, arranger, closet, shelf, notes],
    (err) => {
      if (err) {
        throw err;
      }
      res.redirect("/");
    }
  );
});

app.get("/search", (req, res) => {
  const searchTerm = req.query.term;

  // Set no-cache headers
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate"
  );
  res.setHeader("Expires", "0");
  res.setHeader("Pragma", "no-cache");

  // Modify the query to fit your database structure and search logic
  const searchQuery = `
    SELECT title
    FROM notearchive
    WHERE title LIKE ?
    LIMIT 10;
  `;

  connection.query(searchQuery, [`%${searchTerm}%`], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "An error occurred" });
    }

    const searchResults = results.map((result) => result.title);
    res.json(searchResults);
  });
});

app.post("/update", user.checkAuthenticated, (req, res) => {
  const {
    editEntryId,
    archive_id,
    title,
    composer,
    arranger,
    closet,
    shelf,
    notes,
  } = req.body;
  const updateQuery = `
    UPDATE notearchive
    SET archive_id = ?, title = ?, composer = ?, arranger = ?, closet = ?, shelf = ?, notes = ?
    WHERE id = ?;
  `;
  connection.query(
    updateQuery,
    [archive_id, title, composer, arranger, closet, shelf, notes, editEntryId],
    (err) => {
      if (err) {
        throw err;
      }
      res.redirect("/");
    }
  );
});

app.post("/delete", user.checkAuthenticated, (req, res) => {
  const entryIdToDelete = req.body.entryId;

  const deleteQuery = "DELETE FROM notearchive WHERE id = ?";
  connection.query(deleteQuery, [entryIdToDelete], (err) => {
    if (err) {
      throw err;
    }
    res.redirect("/");
  });
});

// initialize the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
