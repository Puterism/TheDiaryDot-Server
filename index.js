import { GraphQLServer } from 'graphql-yoga'
import { defaultFieldResolver } from 'graphql'
import { SchemaDirectiveVisitor } from 'graphql-tools'
import mongoose from 'mongoose'
import fs from 'fs'
import bodyParser from 'body-parser'
import helmet from 'helmet'
import passport from 'passport'
import passportJWT from 'passport-jwt'
import jwt from 'jsonwebtoken'
import uuid from 'uuid/v4'
const FacebookStrategy = require('passport-facebook').Strategy
const JWTStrategy = passportJWT.Strategy
const ExtractJwt = passportJWT.ExtractJwt

import config from './config'

/*********** MongoDB and Mongoose Settings ***********/
mongoose.connect('mongodb://localhost:27017/TheDiaryDot', { useNewUrlParser: true })

const Schema = mongoose.Schema

const diarySchema = new Schema({
  _id: {type: String},
  date: {type: String},
  content: {type: String},
  userId: {type: String},
  savedDateTime: {type: Date},
  lastSavedDateTime: {type: Date}
}, { _id: false, collection: 'diaries' })

const tempDiarySchema = new Schema({
  date: {type: String},
  content: {type: String},
  userId: {type: String},
  savedDateTime: {type: Date},
}, { _id: false, collection: 'temp_diary'})

const userSchema = new Schema({
  facebookID: {type: String}
})

const Diary = mongoose.model('diaries', diarySchema)
const TempDiary = mongoose.model('temp_diary', tempDiarySchema)
const User = mongoose.model('users', userSchema)


/*********** GraphQL ***********/
const typeDefs = `
  directive @auth on FIELD_DEFINITION

  type Diary {
    _id: String!
    date: String!
    content: String!
    userId: String!
    savedDateTime: String!
    lastSavedDateTime: String!
  }
  
  type Query {
    getDiariesByMonth(year: String, month: String, userId: String): [Diary]! @auth
    getTempDiary(userId: String): Diary @auth
  }
  
  type Mutation {
    addDiary(date: String, content: String, userId: String): Boolean! @auth
    deleteDiary(_id: String, userId: String): Boolean! @auth
    deleteDiaryAll(userId: String): Boolean! @auth
    editDiary(_id: String, date: String, content: String, userId: String): Boolean! @auth
    addTempDiary(date: String, content: String, userId: String): Boolean! @auth
    deleteTempDiary(userId: String): Boolean! @auth
  }
`

const resolvers = {
  Query: {
    getDiariesByMonth: async (_, { year, month, userId }, { req }) => {
      const regexp = new RegExp(`\\b(${year}-${month})-[\\d][\\d]\\b`)
      const diaries = await Diary.find((err) => {
        if (err) {
          return false
        }
      }).where('userId').equals(userId).regex('date', regexp)
      diaries.forEach(diary => {
        const buf = Buffer.from(diary.content, 'base64')
        diary.content = buf.toString('utf8')
      })
      
      return diaries
    },
    getTempDiary: async (_, { userId }) => {
      const tempDiary = await TempDiary.findOne({ userId: userId }, (err) => {
        if (err) {
          return false
        }
      })
      if (tempDiary) {
        tempDiary.content = Buffer.from(tempDiary.content, 'base64').toString('utf8')
        return tempDiary
      }
      return null
    }
  },
  Mutation: {
    addDiary: async (_, { date, content, userId }) => {
      const diary = new Diary()
      const buf = Buffer.from(content, 'utf8')
      diary._id = uuid()
      diary.savedDateTime = new Date().getTime()
      diary.date = date
      diary.content = buf.toString('base64')
      diary.userId = userId
      await diary.save((err) => {
        if (err) return false
      })
      return true
    },
    deleteDiary: async (_, { _id, userId }) => {
      await Diary.deleteOne({ _id: _id, userId: userId }, (err) => {
        if (err) return false
      })
        return true
    },
    deleteDiaryAll: async (_, { userId }) => {
      await Diary.deleteMany({ userId: userId }, (err) => {
        if (err) return false
      })
      return true
    },
    editDiary: async (_, { _id, date, content, userId }) => {
      const diary = new Diary()
      const buf = Buffer.from(content, 'utf8')
      diary.lastSavedDateTime = new Date().getTime()
      diary.content = buf.toString('base64')
      diary.date = date
      await Diary.updateOne({ _id: _id }, { $set: { date: diary.date, content: diary.content, lastSavedDateTime: diary.lastSavedDateTime }}, (err) => {
        if (err) return false
      })
      return true
    },
    addTempDiary: async (_, { date, content, userId }) => {
      await TempDiary.deleteMany({ userId: userId }, (err) => {
        if (err) return false
      })
      const tempDiary = new TempDiary()
      const buf = Buffer.from(content, 'utf8')
      tempDiary.savedDateTime = new Date().getTime()
      tempDiary.date = date
      tempDiary.content = buf.toString('base64')
      tempDiary.userId = userId
      await tempDiary.save((err) => {
        if (err) return false
      })
      return true
    },
    deleteTempDiary: async (_, { userId }) => {
      await TempDiary.deleteMany({ userId: userId }, (err) => {
        if (err) return false
      })
      return true
    }
  }
}

class AuthDirective extends SchemaDirectiveVisitor {
  visitFieldDefinition (field) {
    const { resolve = defaultFieldResolver } = field
    field.resolve = async function (...args) {
      const [, params, context] = args
      const req = context.req
      if (req.headers.authorization) {
        const token = req.headers.authorization.slice(7)
      
        if (token) {
          const decoded = jwt.verify(token, config.jwt.secret)
          if (params.userId === decoded.facebookID) {
            const result = await resolve.apply(this, args)
            return result
          }
        }
      }
      
      throw new Error(
        `You are not authorized.`
      )
    }
  }
}
/*********** graphql-yoga Settings ***********/
const context = (req) => ({
  req: req.request
})

const server = new GraphQLServer({ typeDefs, resolvers, schemaDirectives: { auth: AuthDirective }, context })
server.use(helmet())

/*********** passport ***********/
server.use(bodyParser.urlencoded({ extended: false }));
server.use(passport.initialize())

function generateToken(facebookID) {
  const secret = config.jwt.secret
  const expiresIn = '30 days'
  
  const token = jwt.sign({'facebookID': facebookID}, secret, {
    expiresIn: expiresIn,
    // audience: audience,
    // issuer: issuer,
    // subject: userId.toString()
  })
  
  return token
}

passport.serializeUser(function (user, done) {
  done(null, user)
})

passport.deserializeUser(function (user, done) {
  done(null, user)
})

passport.use(new JWTStrategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey   : config.jwt.secret
},
function (jwtPayload, done) {
  return User.findOne({ facebookID: jwtPayload.facebookID })
    .then(user => {
      return done(null, user);
    })
    .catch(err => {
      return done(err);
    });
}
));

passport.use(
  new FacebookStrategy({
    clientID: config.fb.clientID,
    clientSecret: config.fb.clientSecret,
    callbackURL: 'https://diarydev.puterism.com:8080/api/auth/facebook/callback',
    profileFields: ['id', 'displayName', 'email'],
    enableProof: true
  },
  (accessToken, refreshToken, profile, done) => {
    User.findOne({ facebookID: profile.id }, (err, user) => {
      if (err) {
        return done(err, user)
      }
      if (user) {
        return done(null, user)
      } else {
        User.create({ facebookID: profile.id }, (err, user) => {
          if (err) {
            return done(err, user)
          }
          return done(null, user)
        })
      }
    })
  }
))

server.get('/auth/facebook', passport.authenticate('facebook', {
  session: false,
  authType: 'rerequest', scope: ['public_profile', 'email']
}))

server.get('/auth/facebook/callback',
  passport.authenticate('facebook', {
    session: false,
    failureRedirect: '/'
  }),
  (req, res) => {
    const token = generateToken(req.user.facebookID)
    res.cookie('auth', token)
    res.cookie('fbid', req.user.facebookID)
    res.redirect('/main')
  }
);

server.start(
  {
    port: 8082,
    endpoint: '/graphql',
    playground: '/pg',
    https: {
      key: fs.readFileSync(config.server.privkey),
      cert: fs.readFileSync(config.server.fullchain)
    }
  },
  () => {
  console.log(
    `Server is running`
  );
})
