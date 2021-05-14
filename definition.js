const app = require("@live-change/framework").app()

const definition = app.createServiceDefinition({
  name: "emailPassword"
})

module.exports = definition