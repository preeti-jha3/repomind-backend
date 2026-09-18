const express = require('express');
const { Pool } = require('pg');
const axios = require('axios');
const { GoogleGenAI } = require('@google/genai');
require('dotenv').config();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5000;

// ---- CORS CONFIG ----
const allowedOrigins = [
  'http://localhost:3000',
  'https://repomind-frontend-smoky.vercel.app'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.connect()
  .then(() => console.log('Supabase database is connected!'))
  .catch((err) => console.log('Error in Database connection:', err.message));

const genAI = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

app.get('/', (req, res) => {
  res.send('RepoMind Backend is running!');
});

app.get('/api/analyze', (req, res) => {
  res.json({
    status: 'Success',
    summary: {
      risk: 'High',
      file: 'auth.js - Line 42',
      issue: 'This Code cause Bugs Before',
      fix: 'Add the NULL Check'
    }
  });
});

function getSeverity(message) {
  const lowerMessage = message.toLowerCase();
  const highKeywords = [
    'security',
    'critical',
    'crash',
    'payment',
    'data loss',
    'vulnerability'
  ];

  const mediumKeywords = [
    'error',
    'exception',
    'fail',
    'break'
  ];

  if (highKeywords.some((keyword) => lowerMessage.includes(keyword))) {
    return 'High';
  }

  if (mediumKeywords.some((keyword) => lowerMessage.includes(keyword))) {
    return 'Medium';
  }

  return 'Low';
}

// Generates a plain-language explanation of what bug the commit message fixes.
async function getExplanation(message, retries = 2) {
  try {
    const result = await genAI.models.generateContent({
      model: 'gemini-3.5-flash',

      contents: `A developer wrote this commit message: "${message}".
In 2 simple lines, explain what bug this commit is fixing and why it mattered.
If the message does not actually describe a bug fix, say so plainly instead of guessing.`
    });

    const text =
      result?.text ||
      result?.candidates?.[0]?.content?.parts?.[0]?.text ||
      null;

    if (!text || !text.trim()) {
      console.log(
        'GEMINI EMPTY RESPONSE:',
        JSON.stringify(result, null, 2)
      );
      return null;
    }

    return text.trim();

  } catch (error) {
    const msg = error?.message || String(error);

    if (
      (msg.includes('503') || msg.includes('429')) &&
      retries > 0
    ) {
      await new Promise((r) => setTimeout(r, 2000));
      return getExplanation(message, retries - 1);
    }

    console.log('GEMINI ERROR:', msg);
    return null;
  }
}

app.get('/fetch-commits', async (req, res) => {
  try {
    const owner = req.query.owner || 'facebook';
    const repo = req.query.repo || 'react';

    const limit = Math.min(
      parseInt(req.query.limit) || 10,
      30
    );

    const response = await axios.get(
      `https://api.github.com/repos/${owner}/${repo}/commits`,
      {
        headers: {
          Authorization: `token ${process.env.GITHUB_TOKEN}`
        },
        params: {
          per_page: 100
        }
      }
    );

    const cleanedCommits = response.data.map((commit) => ({
      sha: commit.sha,
      message: commit.commit.message,
      author: commit.commit.author.name,
      date: commit.commit.author.date
    }));

    const bugKeywords = [
      'fix',
      'bug',
      'error',
      'issue',
      'resolve'
    ];

    const bugCommits = cleanedCommits.filter((commit) => {
      const firstPart = commit.message
        .toLowerCase()
        .substring(0, 30);

      return bugKeywords.some((keyword) =>
        firstPart.includes(keyword)
      );
    });

    if (bugCommits.length === 0) {
      return res.json({
        message: 'No commits found',
        commits: []
      });
    }

    const commitsToProcess = bugCommits.slice(0, limit);

    for (const commit of commitsToProcess) {

      const existing = await pool.query(
        'SELECT * FROM commits WHERE sha = $1',
        [commit.sha]
      );

      if (existing.rows.length > 0) {

        const row = existing.rows[0];

        commit.severity = row.severity || 'Low';

        if (!row.explanation) {

          const retryExp = await getExplanation(
            commit.message
          );

          if (retryExp) {

            await pool.query(
              'UPDATE commits SET explanation = $1 WHERE sha = $2',
              [retryExp, commit.sha]
            );

            commit.explanation = retryExp;

          } else {

            commit.explanation =
              'Explanation pending — retry later.';
          }

        } else {

          commit.explanation = row.explanation;
        }

        continue;
      }

      const severity = getSeverity(commit.message);

      const explanation = await getExplanation(
        commit.message
      );

      await pool.query(
        `INSERT INTO commits
        (sha, message, author, date, severity, explanation)
        VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          commit.sha,
          commit.message,
          commit.author,
          commit.date,
          severity,
          explanation
        ]
      );

      commit.severity = severity;

      commit.explanation =
        explanation ||
        'Explanation pending — retry later.';
    }

    res.json({
      message: `${commitsToProcess.length} bug-fix commits saved to database!`,
      commits: commitsToProcess
    });

  } catch (error) {

    res.status(500).json({
      error: error.message
    });
  }
});


// Backfill missing AI explanations
app.get('/api/backfill', async (req, res) => {

  try {

    const { rows } = await pool.query(
      'SELECT sha, message FROM commits WHERE explanation IS NULL'
    );

    let fixed = 0;

    for (const row of rows) {

      const exp = await getExplanation(row.message);

      if (exp) {

        await pool.query(
          'UPDATE commits SET explanation = $1 WHERE sha = $2',
          [exp, row.sha]
        );

        fixed++;
      }

      await new Promise((r) => setTimeout(r, 1200));
    }

    res.json({
      total: rows.length,
      fixed
    });

  } catch (error) {

    res.status(500).json({
      error: error.message
    });
  }
});


// ---- AUTH ROUTES ----

app.post('/api/auth/signup', async (req, res) => {

  try {

    const { name, email, password } = req.body;

    if (!name || !email || !password) {

      return res.status(400).json({
        message: 'All fields are required'
      });
    }

    const existing = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (existing.rows.length > 0) {

      return res.status(400).json({
        message: 'Email already registered'
      });
    }

    const hashedPassword = await bcrypt.hash(
      password,
      10
    );

    const result = await pool.query(
      `INSERT INTO users
      (name, email, password)
      VALUES ($1, $2, $3)
      RETURNING id, name, email`,
      [
        name,
        email,
        hashedPassword
      ]
    );

    res.status(201).json({
      message: 'Signup successful',
      user: result.rows[0]
    });

  } catch (error) {

    res.status(500).json({
      message: error.message
    });
  }
});


app.post('/api/auth/login', async (req, res) => {

  try {

    const { email, password } = req.body;

    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    const user = result.rows[0];

    if (!user) {

      return res.status(400).json({
        message: 'Invalid email or password'
      });
    }

    const isMatch = await bcrypt.compare(
      password,
      user.password
    );

    if (!isMatch) {

      return res.status(400).json({
        message: 'Invalid email or password'
      });
    }

    const token = jwt.sign(
      { id: user.id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });

  } catch (error) {

    res.status(500).json({
      message: error.message
    });
  }
});


// ---- GET ALL SAVED COMMITS ----

app.get('/api/commits', async (req, res) => {

  try {

    const result = await pool.query(
      'SELECT * FROM commits ORDER BY date DESC'
    );

    if (result.rows.length === 0) {

      return res.json({
        message: 'No commits found',
        commits: []
      });
    }

    const commits = result.rows.map((r) => ({
      ...r,

      explanation:
        r.explanation ||
        'Explanation pending — retry later.',

      severity:
        r.severity ||
        'Low'
    }));

    res.json({
      message: `${commits.length} commits loaded`,
      commits
    });

  } catch (error) {

    res.status(500).json({
      error: error.message
    });
  }
});


app.listen(PORT, () => {
  console.log(
    `Server running on http://localhost:${PORT}`
  );
});