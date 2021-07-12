//create server with express
const express = require('express');

//parse our request, need bodyParser
const bodyParser = require('body-parser');

const authRoutes = require('./routes/auth');

const errorController = require('./controllers/error');

//create application with express method
const app = express();

//create port
const ports = process.env.PORT || 3000;

//create middleware
app.use(bodyParser.json());

//CORS - allow access to different pages (express-angular)
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  // res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Custom-Header, Authorization');
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  next();
});

app.use('/auth', authRoutes);

app.use(errorController.get404);

app.use(errorController.get500);

//listen to the port
app.listen(ports, () => console.log(`Listening on port ${ports}`));