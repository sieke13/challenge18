import jwt from 'jsonwebtoken';
import { GraphQLError } from 'graphql';
import dotenv from 'dotenv';
dotenv.config();

// Define a fallback secret key
const JWT_SECRET = process.env.JWT_SECRET_KEY || '25c390a9e5dbadc7ef5d650272ff3fcf63819f3f012106bf68606b3d4e849578';

export const authenticateToken = ({ req }: any) => {
  // Allows token to be sent via req.body, req.query, or headers
  let token = req.body.token || req.query.token || req.headers.authorization;

  // If the token is sent in the authorization header, extract the token from the header
  if (req.headers.authorization) {
    token = token.split(' ').pop().trim();
  }

  // If no token is provided, return the request object as is
  if (!token) {
    return req;
  }

  // Try to verify the token
  try {
    const { data }: any = jwt.verify(token, JWT_SECRET, { maxAge: '2hr' });
    // If the token is valid, attach the user data to the request object
    req.user = data;
  } catch (err) {
    // If the token is invalid, log an error message
    console.log('Invalid token', err);
  }

  // Return the request object
  return req;
};

export const signToken = (username: string, email: string, _id: unknown) => {
  // Create a payload with the user information
  const payload = { username, email, _id };
  
  // Use the defined secret key constant instead of directly accessing env variable
  // This ensures we always have a value
  return jwt.sign({ data: payload }, JWT_SECRET, { expiresIn: '2h' });
};

export class AuthenticationError extends GraphQLError {
  constructor(message: string) {
    super(message, undefined, undefined, undefined, ['UNAUTHENTICATED']);
    Object.defineProperty(this, 'name', { value: 'AuthenticationError' });
  }
};
