
import * as http from 'http';
import express from 'express';
import bodyParser from 'body-parser';
import pg from 'pg';
import bcrypt from 'bcrypt';
import passport from 'passport';
import { Strategy } from 'passport-local';
import session from 'express-session';
import env from 'dotenv';
import GoogleStrategy from 'passport-google-oauth2';
import { createServer } from 'http';
import { Server } from 'socket.io';
import path from 'path';
import { fileURLToPath } from 'url';

const app = express();
const port = 4000;
const saltRounds = 10;
env.config();
const server = http.createServer(app);
const io = new Server(server);
const db = new pg.Client({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // Required for Render PostgreSQL
  },
});
db.connect();


app.use(
  session({
    secret: 'SECRET',
    resave: false,
    saveUninitialized: true,
  })
);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(passport.initialize());
app.use(passport.session());

app.get('/', (req, res) => {
  res.render('Landing.ejs');
});
app.get('/chat/:sender/:receiver', (req, res) => {
  const { sender, receiver } = req.params;
  res.render('chat', { sender, receiver });
});

app.get('/login', (req, res) => {
  res.render('login.ejs');
});
('/register', (req, res) => {
  res.render('login.ejs');
});


app.get('/joingroup', async (req, res) => {
  if (req.isAuthenticated()) {
    const userId=req.user.id; 
    try {
      // console.log(CURRENT_DATE);
      //  await db.query('DELETE FROM user_data WHERE date < CURRENT_DATE');
      await db.query('DELETE FROM user_data WHERE date < CURRENT_DATE');
        // const res1 = await db.query('SELECT * FROM user_data WHERE date <= CURRENT_DATE');
        //   console.log(res1.rows);

      const result2 = await db.query('SELECT username,profilepic FROM users WHERE id = $1', [userId]);
      const result = await db.query(`
  SELECT user_data.*, users.username, users.profilepic ,users.about
  FROM user_data 
  JOIN users ON user_data.user_id = users.id
`);

      // console.log(result);
      res.render('joingroup.ejs', { data: result.rows,username: result2.rows[0].username,
        profilepic: result2.rows[0].profilepic });
    } catch (error) {
      console.error('Error fetching data:', error);
      res.status(500).send('Internal Server Error');
    }
  } else {
    res.redirect('/login');
  }
});


app.get('/yourgroup',async(req,res)=>{
  // console.log("correct");  
  if (req.isAuthenticated()) {
  const userId=req.user.id;
  try {
    const result2 = await db.query('SELECT username,profilepic FROM users WHERE id = $1', [userId]);
    const result = await db.query('SELECT * FROM user_data WHERE user_id = $1 ',[userId]);
    
    res.render('yourgrp.ejs', { data: result.rows,username: result2.rows[0].username,
      profilepic: result2.rows[0].profilepic });
  } catch (error) {
    console.error('Error fetching data:', error);
    res.status(500).send('Internal Server Error');
  }
  } else {
  res.redirect('/login');
}
})

app.get("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    req.session.destroy((err) => {
      if (err) {
        console.error("Error destroying session:", err);
      }
      res.redirect("/");
    });
  });
});
app.use((req, res, next) => {
  res.set(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate"
  );
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  res.set("Surrogate-Control", "no-store");
  next();
});


// Assuming you have a database client instance called `db`
// Ensure you have a route to handle DELETE requests
app.delete('/delete-entry/:id', async (req, res) => {
  const entryId = req.params.id;

  try {
      const deleteQuery = 'DELETE FROM user_data WHERE id = $1';
      const result = await db.query(deleteQuery, [entryId]);

      if (result.rowCount > 0) {
          res.json({ success: true, message: 'Entry deleted successfully' });
      } else {
          res.status(404).json({ success: false, message: 'Entry not found' });
      }
  } catch (error) {
      console.error('Error deleting entry:', error);
      res.status(500).json({ success: false, message: 'Failed to delete entry' });
  }
});
app.delete('/delete-message/:id', async (req, res) => {
  const messageId = req.params.id;

  try {
    const deleteQuery = 'DELETE  FROM messages WHERE id = $1';
    const result = await db.query(deleteQuery, [messageId]);

    if (result.rowCount > 0) {
      res.json({ success: true, message: 'Message deleted successfully' });
    } else {
      res.status(404).json({ success: false, message: 'Message not found' });
    }
  } catch (error) {
    console.error('Error deleting message:', error);
    res.status(500).json({ success: false, message: 'Failed to delete message' });
  }
});


app.put('/edit', async(req, res) => {
  if(req.isAuthenticated()){
    const entryId=req.user.id;
    console.log("edit");
  
  const { vacancy, time, from_location, to_location, date, type } = req.body;
  

  const sql = `UPDATE user_data SET vacancy = ?, time = ?, from_location = ?, to_location = ?, date = ?, type = ? WHERE id = ?`;
  db.query(sql, [vacancy, time, from_location, to_location, date, type, entryId], (err, result) => {
      if (err) {
          // console.error(err);
          return res.status(500).json({ success: false, message: 'Failed to update entry' });
      }
      res.json({ success: true });
  });}
});

app.get('/group', async(req, res) => {
  if (req.isAuthenticated()) {
   const userId=req.user.id;
    try {
      const result = await db.query('SELECT username,profilepic FROM users WHERE id = $1', [userId]);
      // res.json({ messages: result.rows });
      // console.log(result.rows[0].username);
      res.render('group.ejs',{username: result.rows[0].username,
        profilepic: result.rows[0].profilepic});
  } catch (error) {
      console.error('Error fetching messages:', error);
      res.status(500).json({ error: 'Failed to fetch messages' });
  }
    
  } else {
    res.redirect('/login');
  }
});

app.get('/auth/google', passport.authenticate('google', {
  scope: ['profile', 'email'],
}));

app.get('/auth/google/group',
  passport.authenticate('google', {
    successRedirect: '/group',
    failureRedirect: '/login',
  })
);

app.get("/test-db", async (req, res) => {
  try {
    const result = await db.query("SELECT NOW()");
    res.send("✅ Database Connected! Current Time: " + result.rows[0].now);
  } catch (err) {
    console.error("❌ Database connection error:", err);
    res.status(500).send("❌ Database connection failed.");
  }
});

app.get('/group/myprofile', async (req, res) => {
  try {
    if (req.isAuthenticated()) {
      // Assuming req.user has all user fields: name, phone, about, profilepic
      // If not, you may need to query your DB here to get full user info

      // Construct user object to pass to EJS
      const user = {
        username: req.user.username || '',
        phone: req.user.phone || '',
        about: req.user.about || '',
        profilepic: req.user.profilepic || ''
      };

      return res.render('myprofile.ejs', { user });
    } else {
      // User not authenticated — redirect to login or send 401
      return res.redirect('/login');
    }
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Server Error' });
  }
});

import multer from 'multer';
app.use('/uploads', express.static('uploads')); 
const upload = multer({ dest: 'uploads/' }); // configure storage as needed
app.use('/uploads', express.static('public/uploads'));
app.post('/updateProfile', upload.single('profilepic'), async (req, res) => {
  const { username, phone, about } = req.body;
  let profilepicPath;

  if (req.file) {
    profilepicPath = '/uploads/' + req.file.filename; // example path
  }

  try {
    // Build query and values dynamically based on which fields are present
    const fields = ['username', 'phone', 'about'];
    const values = [username, phone, about];
    let query = 'UPDATE users SET username = $1, phone = $2, about = $3';
    let paramIndex = 4;

    if (profilepicPath) {
      query += `, profilepic = $${paramIndex}`;
      values.push(profilepicPath);
      paramIndex++;
    }

    query += ` WHERE id = $${paramIndex}`;
    values.push(req.user.id);

    await db.query(query, values);

    res.redirect('/group/myprofile');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});


app.post('/create', async (req, res) => {
  if (req.isAuthenticated()) {
    const { vacancy, time, date, from_location, to_location, type } = req.body;

    const userId = req.user.id;

    try {
      await db.query(
        'INSERT INTO user_data (vacancy, time, date, from_location, to_location, user_id, type) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [vacancy, time, date, from_location, to_location, userId, type]
      );
      res.redirect('/group');
    } catch (error) {
      console.error('Error creating group:', error);
      res.status(500).send('Internal Server Error');
    }
  } else {
    res.redirect('/login');
  }
});

app.post('/login', passport.authenticate('local', {
  successRedirect: '/group',
  failureRedirect: '/login',
}));
app.use(express.json());  // Ensure this middleware is present

// Add this route to handle message sending
app.post('/sendMessage', async (req, res) => {
  if (req.isAuthenticated()) {
    const { userId, message } = req.body;
    
    const senderId = req.user.id; // Get the ID of the logged-in user

    try {
      await db.query(       
        'INSERT INTO messages (user_id, sender_id, message) VALUES ($1, $2, $3)',
        [userId, senderId, message]
      );
      res.json({ success: true });
    } catch (error) {
      console.error('Error sending message:', error);
      res.json({ success: false });
    }
  } else {
    res.status(401).json({ success: false });
  }
});


app.get('/fetchMessages', async (req, res) => {
  if (req.isAuthenticated()) {
    const userId = req.user.id;

    try {
      const result = await db.query(`
        SELECT m.message, u.username, u.profilepic, u.about
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.user_id = $1
        ORDER BY m.id DESC
      `, [userId]);
        // console.log(result.rows);
      res.json({ messages: result.rows });
    } catch (error) {
      console.error('Error fetching messages:', error);
      res.status(500).json({ error: 'Failed to fetch messages' });
    }
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
});

app.get('/messages', async (req, res) => {
  try {
    if (!req.isAuthenticated()) {
      return res.redirect('/login');
    }
     const userId = req.user.id;
    const result1 = await db.query('SELECT username,profilepic FROM users WHERE id = $1', [userId])
    const result = await db.query(`
  SELECT m.id, m.message, u.username, u.profilepic, u.about
  FROM messages m
  JOIN users u ON m.sender_id = u.id
  WHERE m.user_id = $1
  ORDER BY m.id DESC
`, [userId]);


    res.render('message', { messages: result.rows ,username: result1.rows[0].username,
        profilepic: result1.rows[0].profilepic});
  } catch (err) {
    console.error('Error fetching messages:', err);
    res.status(500).send('Server error');
  }
});


app.post('/register', async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query('SELECT * FROM users WHERE email = $1', [email]);

    if (checkResult.rows.length > 0) {
      res.send("<script>alert('Email already exists'); window.location='/login';</script>");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error('Error hashing password:', err);
          res.status(500).send('Internal Server Error');
        } else {
          const result = await db.query(
            'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *',
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            if (err) {
              console.error('Error logging in user:', err);
              res.status(500).send('Internal Server Error');
            } else {
              
              res.redirect('/group');
            }
          });
        }
      });
    }
  } catch (err) {
    
    res.status(500).send('Internal Server Error');
  }
});
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);
passport.use(
  'local',
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query('SELECT * FROM users WHERE email = $1', [username]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error('Error comparing passwords:', err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb('User not found');
      }
    } catch (err) {
      
    }
  })
);

passport.use(
  'google',
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'https://cabclique.onrender.com/auth/google/group',
      userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [profile.email]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            'INSERT INTO users (email, password,username,profilepic) VALUES ($1, $2,$3,$4)',
            [profile.email, 'google',profile.given_name,profile.picture]
          );
          return cb(null, newUser.rows[0]);
        } else {
          
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);
app.use((req, res, next) => {
  res.set(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate"
  );
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  res.set("Surrogate-Control", "no-store");
  next();
});
app.use((req, res, next) => {
  res.set(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate"
  );
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  res.set("Surrogate-Control", "no-store");
  next();
});
// Middleware to prevent caching
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(passport.initialize());
app.use(passport.session());

// 🔥 Add this to prevent back-button login after logout
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

passport.serializeUser((user, cb) => {
  cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
    cb(null, result.rows[0]);
  } catch (err) {
    cb(err);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
