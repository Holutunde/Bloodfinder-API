require('dotenv').config()
require('express-async-errors')

const express = require('express')
const formData = require('express-form-data')
const app = express()
const morgan = require('morgan')
const connectDB = require('./database/db')
const errorHandler = require('./middleware/errorHandler')
const notFound = require('./middleware/notFound')

const users = require('./server/routes/users')

if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'))
}

app.use(formData.parse())
app.use(express.json())
app.use(express.urlencoded({ extended: false }))

app.use('/bloodfinder/users', users)

app.use(errorHandler)
app.use(notFound)

const port = process.env.PORT || 3000

const start = async () => {
  try {
    await connectDB(process.env.MONGO_URI)
    app.listen(port, () =>
      console.log(`Server is listening on port ${port}...`),
    )
  } catch (error) {
    console.log(error)
  }
}

start()
