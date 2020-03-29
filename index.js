const app = require('./app.js')

const definition = require("./definition.js")
definition.validators = require("./validation.js")
const autoSecurityProcessor = require('../security-service/autoSecurity.js')

require("./crud.js")

require("./register.js")
require("./login.js")

require("./emailChange.js")
require("./passwordChange.js")

module.exports = definition

async function start() {
  app.processServiceDefinition(definition, [ ...app.defaultProcessors, autoSecurityProcessor ])
  await app.updateService(definition)//, { force: true })
  const service = await app.startService(definition, { runCommands: true, handleEvents: true })

  /*require("../config/metricsWriter.js")(definition.name, () => ({

  }))*/
}

if (require.main === module) start().catch( error => { console.error(error); process.exit(1) })
