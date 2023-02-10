import express, { json, Request, Response } from 'express'
import * as uuid from 'uuid'
import jsonwebtoken from 'jsonwebtoken'
import * as jwt from 'jsonwebtoken';
import * as Joi from '@hapi/joi';
import bcrypt from 'bcrypt'
import { string } from '@hapi/joi';
const id = uuid.v4().toString
const app = express()

const saltRounds = 7;
const secret = 'secretKey';

// middleware

app.use(json())

const userSchema = Joi.object({
  id: Joi.number().required(),
  name: Joi.string().required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(7).required()
});

const user: {} = {
  id: id,
  name: 'simon muturi',
  email: 'simomutu8@gmail.com.com',
  password: '@Looks.ke'
};

const validationResult = userSchema.validate(user);

if (validationResult.error) {
  console.error(validationResult.error.message);
} else {
  console.log('User is valid!');
  // res.status(200).json({message:""})
}


// An interface to represent the user data structure
interface User {
  id: number;
  name: string;
  email: string;
  password: string;
}

// An array to store the registered users
const users: User[] = [];

// A function to encrypt the password
async function hashPassword(password: string): Promise<string> {
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  return hashedPassword;
}

// A function to validate the email and check for duplicates
function isValidEmail(email: string): boolean {
  for (const user of users) {
    if (user.email === email) {
      return false;
    }
  }
  return true;
}

// A function to register a user
async function registerUser(name: string, email: string, password: string): Promise<string> {
  if (!isValidEmail(email)) {
    throw new Error('Email already exists');
  }

  const hashedPassword = await hashPassword(password);
  const newUser: User = {
    id: users.length + 1,
    name,
    email,
    password: hashedPassword,
  };
  users.push(newUser);

  const token = jwt.sign({ id: newUser.id }, secret);
  return token;
}

// A function to reset the password
async function resetPassword(userId: number, newPassword: string): Promise<void> {
  for (const user of users) {
    if (user.id === userId) {
      user.password = await hashPassword(newPassword);
      return;
    }
  }
  throw new Error('User not found');
}


function searchUsersByName(name: string): User[] {
  const foundUsers: User[] = [];
  for (const user of users) {
    if (user.name.includes(name)) {
      foundUsers.push(user);
    }
  }
  return foundUsers;
}


function verifyToken(req: express.Request, res: express.Response, next: express.NextFunction) {
  const token = req.headers['x-access-token'];
  if (!token) {
    return res.status(401).send('Unauthorized request');
  }

  try {
    const decoded = jwt.verify(token, secret);
    req.body.userId = decoded.id;
    next();
  } catch (err) {
    return res.status(400).send('Invalid token');
  }
}


// Endpoint to register a user
app.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const token = await registerUser(name, email, password);
    res.status(200).send({ token });
  } catch (error) {
    res.status(400).json(error);
  }
});


// reset the password
app.put('/reset', verifyToken, async (req, res) => {
  try {
    const { newPassword } = req.body;
    await resetPassword(req.body.userId, newPassword);
    res.status(200).send('Password reset successful');
  } catch (error) {
    res.status(400).json(error);
  }
});

// search for users by name
app.get('/search', verifyToken, (req, res) => {
  try {
    const { name } = req.query;
    const foundUsers = searchUsersByName(name);
    res.status(200).send(foundUsers);
  } catch (error) {
    res.status(400).json(error);
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
