const app = require('./app.js')

const definition = app.createServiceDefinition({
  name: "emailPassword"
})

module.exports = definition