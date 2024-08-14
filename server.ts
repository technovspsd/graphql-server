import { ApolloServer, gql } from 'apollo-server';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
dotenv.config();
// JWT Secret Key
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error('JWT_SECRET is not defined in .env file');
}
// In-memory users (hardcoded)
const users = [
  {
    id: '1',
    email: 'user1@example.com',
    password: bcrypt.hashSync('password1', 10),
  },
  {
    id: '2',
    email: 'user2@example.com',
    password: bcrypt.hashSync('password2', 10),
  },
];

const typeDefs = gql`
  type User {
    id: ID!
    email: String!
  }

  type AuthPayload {
    token: String!
    user: User!
  }

  type Query {
    currentUser: User
  }

  type Mutation {
    login(email: String!, password: String!): AuthPayload!
  }
`;

const resolvers = {
  Query: {
    currentUser: (_, __, { user }) => {
      if (!user) throw new Error('Not authenticated');
      return user;
    },
  },
  Mutation: {
    login: async (_: any, { email, password }: any) => {
      console.log('Login attempt:', email);
      
      const user = users.find(user => user.email === email);
    
      if (!user) {
        console.log('No user found with this email');
        throw new Error('No user found with this email');
      }
    
      const valid = await bcrypt.compare(password, user.password);
      console.log('Password valid:', valid);
    
      if (!valid) {
        console.log('Invalid password');
        throw new Error('Invalid password');
      }
    
      // Generate JWT
      const token = jwt.sign(
        { userId: user.id, email: user.email },
        JWT_SECRET,
        { expiresIn: '1d' }
      );
    
      console.log('Generated Token on Backend:', token);
    
      return {
        token,
        user: {
          id: user.id,
          email: user.email,
        },
      };
    },
}};

const context = ({ req }: any) => {
  const token = req.headers.authorization || '';
  let user = null;

  if (token) {
    try {
      const decodedToken = jwt.verify(token, JWT_SECRET) as any;
      user = { id: decodedToken.userId, email: decodedToken.email };
    } catch (e) {
      console.log('Invalid token');
    }
  }

  return { user };
};


const server = new ApolloServer({ typeDefs, resolvers, context });

server.listen().then(({ url }) => {
  console.log(`Server ready at ${url}`);
});
