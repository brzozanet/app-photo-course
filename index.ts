import dotenv from "dotenv";
import express from "express";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import bcrypt from "bcrypt";
import { PrismaClient } from "@prisma/client";

dotenv.config();

const prisma = new PrismaClient();
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Sesja
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

// Passport init
app.use(passport.initialize());
app.use(passport.session());


// Passport Local Strategy
passport.use(new LocalStrategy({
    usernameField: 'email'
  },
  async function(email, password, done) {
    try {
      const user = await prisma.user.findUnique({ where: { email } });
      if (!user) return done(null, false, { message: 'Nieprawidłowy email' });

      const valid = await bcrypt.compare(password, user.password);
      if (!valid) return done(null, false, { message: 'Złe hasło' });

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await prisma.user.findUnique({ where: { id } });
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Routing register

app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) return res.status(400).json({ message: 'Email już zarejestrowany' });

  const hashed = await bcrypt.hash(password, 10);
  const user = await prisma.user.create({ data: { email, password: hashed } });
  res.status(201).json({ message: 'Utworzono konto', userId: user.id });
});

// Routing login

app.post('/login', passport.authenticate('local'), (req, res) => {
  res.json({ message: 'Zalogowano', user: req.user });
});

// Routing logout

app.post('/logout', (req, res) => {
  req.logout(() => {
    res.json({ message: 'Wylogowano' });
  });
});

// Middleware auth

function ensureAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.status(401).json({ message: 'Niezalogowany' });
}

// Sample route

app.get('/profile', ensureAuth, (req, res) => {
  res.json({ user: req.user });
});

// Run serv

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Serwer działa na porcie ${PORT}`);
});

