const r = require.main.rethinkdb || require('rethinkdb')
if (require.main === module) require.main.rethinkdb = r

const rtcms = require("../../RTCms")
const definition = require("./definition.js")

require("./crud.js")

require("./register.js")
require("./login.js")

require("./emailChange.js")
require("./passwordChange.js")

module.exports = definition

async function start() {
  rtcms.processServiceDefinition(definition, [ ...rtcms.defaultProcessors ])
  await rtcms.updateService(definition)//, { force: true })
  const service = await rtcms.startService(definition, { runCommands: true, handleEvents: true })
}

if (require.main === module) start().catch( error => { console.error(error); process.exit(1) })

