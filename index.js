import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";

const app = express();
const port = 3000;
const saltRounds = 10;

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "online_store_website",
  password: "1234",
  port: 5432,
});
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: "TOPSECRETWORD",
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.get("/", async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM products");
    const products = result.rows;
    res.render("home.ejs", { products });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server Error");
  }
});

app.get("/cart", async (req, res) => {
  if(req.isAuthenticated()){
    const result = await db.query(
      `select c.product_id, c.quantity, name, description, price, image_url
      from cart c join products p on c.product_id = p.product_id
      where client_id = $1;`,
      [req.user.client_id]
    );
    const products = result.rows;
    res.render("cart.ejs", {products});
  }
  else{
    res.render("login.ejs");
  }
});

app.post("/cart/buy", async (req, res) =>{
  try {
    const user_id = req.user.client_id;
    
    await db.query('DELETE FROM cart  WHERE client_id = $1',
      [user_id]
    );

    res.redirect('/');
} catch (error) {
    console.error(error);
    res.status(500).send("Server Error");
}
});

app.post("/cart/add", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const user_id = req.user.client_id;
      const product_id = req.body.product_id;
      // Check if the product is already in the cart
      const existingItem = await db.query(
          'SELECT * FROM cart WHERE client_id = $1 AND product_id = $2',
          [user_id, product_id]
      );

      if (existingItem.rows.length > 0) {
          // Update quantity
          await db.query(
              'UPDATE cart SET quantity = quantity + 1 WHERE client_id = $1 AND product_id = $2',
              [user_id, product_id]
          );
      } else {
          // Insert new item
          await db.query(
              'INSERT INTO cart (client_id, product_id) VALUES ($1, $2)',
              [user_id, product_id]
          );
      }

      res.redirect("/");
  } catch (error) {
      console.error(error);
      res.status(500).send("Server Error");
  }
  } else {
    res.redirect("/login");
  }

});

app.post("/cart/remove", async (req, res) => {
    try {
      const user_id = req.user.client_id;
      const product_id = req.body.product_id;

      await db.query(
          'DELETE FROM cart WHERE client_id = $1 AND product_id = $2',
          [user_id, product_id]
      );

      res.redirect("/cart");
  } catch (error) {
      console.error(error);
      res.status(500).send("Server Error");
  }

});

// #region Login/Register

app.get("/login", (req, res) => {
  const message = req.query.message || null;
  res.render("login.ejs", { message });
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.post("/register", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;
  const first_name = req.body.first_name;
  const last_name = req.body.last_name;

  try {
    const checkResult = await db.query(
      "SELECT * FROM clients WHERE email = $1",
      [email]
    );

    if (checkResult.rows.length > 0) {
      return res.render("register.ejs", { message: "Email already exists" });
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO clients (email, password, first_name, last_name) VALUES ($1, $2, $3, $4) RETURNING *",
            [email, hash, first_name, last_name]
          );
          console.log(result);
          const user = result.rows[0];

          req.login(user, (err) => {
            console.log(user);

            console.log("success");
            res.redirect("/");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login?message=Wrong+password+or+the+user+does't+exist.",
  })
);

passport.use(
  new Strategy(
    {
      usernameField: "email", // Map "username" to "email"
      passwordField: "password", // Ensure "password" is mapped correctly
    },
    async function verify(email, password, cb) {
      try {
        const result = await db.query(
          "SELECT * FROM clients WHERE email = $1 ",
          [email]
        );
        if (result.rows.length > 0) {
          const user = result.rows[0];
          const storedHashedPassword = user.password;
          bcrypt.compare(password, storedHashedPassword, (err, valid) => {
            if (err) {
              //Error with password check
              console.error("Error comparing passwords:", err);
              return cb(err);
            } else {
              if (valid) {
                //Passed password check
                return cb(null, user);
              } else {
                //Did not pass password check
                return cb(null, false);
              }
            }
          });
        } else {
          return cb("User not found");
        }
      } catch (err) {
        console.log(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

// #endregion

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
